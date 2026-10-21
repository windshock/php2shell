# PHP2Shell 정적·동적 분석 결과 보고서 (패치 전, PHP 8.4.4 / 8.5.4)

> 기준 시각: 2026-10-21 (공식 패치 23:00 KST 공개 전) · 대상: `sources/php-src-php-8.4.4`(Windows 원본 ZIP) 및 WSL 순정 빌드 `8.4.4-normal`/`8.4.4-asan`/`8.5.4-asan` · 계획: [php2shell-analysis-plan.md](php2shell-analysis-plan.md)
>
> **판정 표기**: A = 원본 코드에서 직접 확인(파일:라인), B = 로컬 랩 관측, C = 이번 분석으로 확인 못함/미확정. 본 문서는 공식 패치 공개 전 스냅샷이며 CVE 확정 판정이 아니다.

## 1. 정적 분석 결과 (Phase 1)

### S1. 업로드 진행 구조체의 zval 포인터 장기 보관 — **확인 (A)**

`ext/session/php_session.h:122-139`의 `php_session_rfc1867_progress` 구조체:

```c
zval      data;                 /* the array exported to session data */
zval      files;                /* data["files"] array */
zval     *post_bytes_processed; /* data["bytes_processed"] */        ← L136
zval     *current_file_bytes_processed;                              ← L137
```

또한 `php_session.h:193`이 요청 범위 전역 `PS(rfc1867_progress)`로 이 구조체를 보관한다. 보고서의 "내부 `zval *` 장기 보관" 구조 주장은 사실이다.

### S2. 콜백의 포인터 취득과 직접 쓰기 — **확인 (A)**

`ext/session/session.c`의 `php_session_rfc1867_callback()`(L3207~):

| 이벤트 | 동작 | 위치 |
|---|---|---|
| START | `progress = ecalloc(...)`, `PS(rfc1867_progress) = progress` | L3219-3226 |
| FORMDATA | 세션 이름과 같은 폼 필드(기본 `PHPSESSID`) 값을 `progress->sid`로 저장 / `PHP_SESSION_UPLOAD_PROGRESS` 필드로 진행 키 구성 + `early_find_sid` | L3246-3260 |
| FILE_START(첫) | `progress->data` 배열 생성 후 `progress->post_bytes_processed = zend_hash_str_find(Z_ARRVAL(progress->data), "bytes_processed", ...)` — **내부 버킷 포인터 취득**; `php_rinit_session(0)` + `PS(id)`에 sid 반영 | L3291, L3293-3295 |
| FILE_START(매 파일) | `progress->current_file_bytes_processed = zend_hash_str_find(Z_ARRVAL(progress->current_file), ...)` 후 즉시 `Z_LVAL_P()` 쓰기 | L3311-3313 |
| FILE_DATA | `Z_LVAL_P(progress->current_file_bytes_processed) = data->offset + data->length; Z_LVAL_P(progress->post_bytes_processed) = data->post_bytes_processed;` — **참조 검사 없는 저장 포인터 직접 쓰기** | L3326-3327 |
| FILE_END | `Z_LVAL_P(progress->post_bytes_processed)` 쓰기 후 update | L3350-3351 |
| END | cleanup 또는 최종 update → `php_rshutdown_session_globals()` → `zval_ptr_dtor(&progress->data)` → `efree(progress)` → `PS(rfc1867_progress)=NULL` | L3358-3386 |

포인터 취득·직접 쓰기 메커니즘 자체는 보고서/PoC A 설명대로 존재한다. 단, 아래 S3이 보이듯 **수명은 보호된다**.

### S3. `Z_TRY_ADDREF(progress->data)`와 참조 수명 — **확인: 원본에서 포인터 UAF 가설 반박 (A)**

`php_session_rfc1867_update()`(session.c:3161-3193):

```c
php_session_initialize();                       /* 세션 로드(디코딩) — L3182 */
PS(session_status) = php_session_active;
IF_SESSION_VARS() {
    zval *sess_var = Z_REFVAL(PS(http_session_vars));
    SEPARATE_ARRAY(sess_var);
    progress->cancel_upload |= php_check_cancel_upload(progress);
    Z_TRY_ADDREF(progress->data);               /* ← L3189 */
    zend_hash_update(Z_ARRVAL_P(sess_var), progress->key.s, &progress->data);  /* L3190 */
}
php_session_flush(1);                           /* 세션 인코딩·기록 — L3192 */
```

- `php_session_track_init()`(session.c:236-250)은 "Unconditionally destroy existing array" 주석 그대로 기존 `$_SESSION` 배열을 파괴하고 새로 만든다. 그러나 update는 매번 `Z_TRY_ADDREF`로 `progress->data` 배열 참조를 1 늘리고 나서 `$_SESSION`에 삽입하므로, `$_SESSION` 교체로 참조가 빠져도 **progress 자신의 참조가 배열을 살려둔다**. FILE_DATA/FILE_END의 `Z_LVAL_P()` 쓰기는 항상 살아 있는 배열을 대상으로 한다.
- END 이벤트의 비-cleanup 경로(L3364-3370)는 `SEPARATE_ARRAY(&progress->data)`로 배열을 복제한 뒤 `Z_LVAL_P(progress->post_bytes_processed)`를 쓰는데, 이 쓰기 대상(구 배열)은 그 시점까지 `$_SESSION`이 소유한 채 살아 있고, 그 뒤 `zend_hash_update`가 구 값을 교체·해제한 뒤에는 해당 포인터를 다시 사용하는 코드가 없다.
- 결론: **8.4.4 원본에서 "세션 재초기화 → 배열 해제 → 포인터 재사용" 경로는 성립하지 않는다.** 이는 독립 감사(xuehuolll)의 ablation 결과(해당 줄 제거 시에만 UAF)와 정확히 일치한다. PoC A(eness)의 근본 원인 주장은 코드 수준에서 반박된다.

### S4. `BG(serialize)` 요청 간 상태 재사용 가설 — **구조적으로 성립 가능 (A, 동적 검증은 §2)**

사슬을 이루는 네 가지 사실을 원본에서 확인했다:

1. **직렬화 상태의 재사용 캐시**: `ext/standard/var.c:1326-1342`의 `php_var_serialize_init()`는 `BG(serialize).level > 0`이면 새 컨텍스트를 만들지 않고 `BG(serialize).data`를 그대로 재사용한다. `php_var_serialize_destroy()`(var.c:1344-1353)는 짝이 맞아야 level을 0으로 만든다.
2. **초기화 시점**: `ext/standard/basic_functions.c:405-407` — basic 모듈 RINIT에서 `memset(&BG(serialize), 0, ...)`. 즉 BG(serialize)는 **요청 시작 시**(모듈 RINIT에서) 초기화된다.
3. **실행 순서**: `main/main.c:1871-1872` — `php_hash_environment()`(POST/multipart 파싱 → 업로드 진행 콜백 → 세션 초기화·디코딩·flush)가 `zend_activate_modules()`(모듈 RINIT, basic 포함)보다 **먼저** 실행된다. 따라서 multipart 파싱 중 실행되는 직렬화는 **이전 요청이 남긴 BG(serialize) 값을 본다**.
4. **세션 flush가 php_var_serialize 경유**: `ext/session/session.c:1061-1088` — 기본 `php` 직렬화 핸들러가 `PHP_VAR_SERIALIZE_INIT`/`php_var_serialize`를 사용한다. 업로드 진행 update 중 `php_session_flush(1)`(session.c:3192)이 세션을 인코딩하므로, **사용자 코드 실행 전에 BG(serialize) 체계가 동작한다**.

잔류 발생 조건(가설의 빈틈): 인코딩 도중 치명 오류로 `zend_bailout`이 나면 `PHP_VAR_SERIALIZE_DESTROY`(session.c:1088)가 건너뛰어져 `BG(serialize).level > 0`인 채 요청이 끝난다. `php_session_decode`는 `zend_try`로 보호되지만(session.c:265-276) **인코딩 경로에는 그런 보호가 없다**. 요청 종료 시 `shutdown_memory_manager()` → `zend_mm_shutdown()`(zend_alloc.c:2394-2404)이 tracked 할당 전체를 `free()`하므로 `BG(serialize).data`는 매달린 포인터가 되고, 다음 요청의 파싱 중 직렬화가 이를 재사용하면 **use-after-free**가 된다.

**치명 오류의 현실적 발생원**: `memory_limit`. Zend 할당기뿐 아니라 **tracked 할당기도 우아한 치명 오류로 한도를 강제**한다 — `zend_alloc.c:2949-2961`의 `tracked_check_limit()`가 `zend_mm_safe_error()`("Allowed memory size of ... exhausted")를 호출한다. 즉 `USE_ZEND_ALLOC=0, USE_TRACKED_ALLOC=1` + ASAN 조합에서 (1) memory_limit 초과가 bailout을 일으키고 (2) 요청 종료 시 실제 `free()`가 일어나 ASAN이 잔류 재사용을 볼 수 있다. 독립 연구의 "특수 ASAN/추적 할당 환경"이 이 구성으로 해석된다. (zend 기본 할당기에서는 Zend MM 풀이 재활용해 ASAN이 오류를 보지 못할 수 있다.)

### S5. 요청 시작 순서 — **확인 (A)**

`php_request_startup()`(main.c): `php_hash_environment()`(L1871) → `zend_activate_modules()`(L1872). 업로드 진행 콜백은 파싱 중 실행되므로 **애플리케이션 코드·로그인 검증 이전**에 세션 초기화·직렬화가 일어난다. 세션은 콜백 내부에서 `php_rinit_session(0)`(session.c:3293)으로 자체 시작된다. "무인증 도달성" 주장의 구조적 근거로 타당하다(단, 이것이 곧 RCE를 의미하지는 않음).

### S6. 8.4.4 ↔ 8.5.4 비교 — **해당 영역 변경 없음 (A)**

`linux/version-diff.sh`로 순정 소스 8개 파일을 비교했다(`var/linux-evidence/evidence/version-diff-8.4.4-8.5.4.txt`, 3,918줄).

- `ext/session/mod_files.c`: **차이 없음**.
- `session.c` rfc1867 영역(구 라인 3095-3390): 14개 hunk는 전부 표면 리팩터링(`ZEND_STRL` 매크로, `zend_string_equals_cstr`, `int→bool`, 주석 정리). **`Z_LVAL_P()` 포인터 쓰기와 `Z_TRY_ADDREF(progress->data)`는 동일하게 존재**.
- `var.c`의 BG(serialize) 초기화/파괴(구 라인 1326-1353), `basic_functions.c` RINIT의 BG 리셋(구 라인 401-407), `main.c`의 `php_hash_environment`→`zend_activate_modules` 순서(구 라인 1820-1885): **변경 없음**.
- var.c의 실질 변경은 배열 재귀 보호 방식(구 라인 998 부근, `Z_PROTECT_RECURSION` 제거)뿐으로 직렬화 상태 수명과는 무관하다.
- 결론: 두 버전 모두 동일한 도달성·참조 보호·BG(serialize) 구조를 가진다. "특정 버전만 영향" 여부는 이 차이만으로는 판단할 수 없다.

### S7. 세션 ID 취득 경로 (ikow 주장 / PR #22113 관련) — **부분 확인 (A)**

- multipart 폼 필드 중 이름이 `session.name`(기본 `PHPSESSID`)과 같은 필드는 `use_only_cookies=On`과 무관하게 **항상** `progress->sid`로 채택된다(session.c:3246-3250). `php_session_rfc1867_early_find_sid()`(session.c:3121-3137)의 `use_only_cookies` 검사는 쿠키/GET 폴백만 제한하며 폼 필드 경로를 막지 않는다.
- `PS_VALIDATE_SID_FUNC(files)`(mod_files.c:699-704)는 `ps_files_key_exists()` — **파일 존재**를 검사한다. `session.use_strict_mode=On`이면 존재하지 않는 sid는 새 무작위 sid로 대체되지만, **존재하는 세션의 sid는 폼 필드로 지정한 채 통과**한다.
- `ps_files_open()`(mod_files.c:152-196)은 `O_CREAT|O_RDWR`로 파일을 열어 **읽기 시 존재하지 않는 세션 파일을 생성**한다. strict mode가 Off면 공격자 지정 이름의 세션 파일이 새로 만들어지고 진행 데이터가 기록된다(파일명 문자집합은 `php_session_valid_key`로 제한: A-Z a-z 0-9 `-` `,`).
- 종합: "쿠키 없이 multipart 폼 필드만으로 세션 지정 가능"이라는 ikow 주장의 코드 근거는 존재한다. 이는 업로드 진행 경로의 전제 조건(유효 세션)을 인증 없이 충족시키는 **도달성 확장** 요소다. 단, 이것만으로는 PHP 코어 RCE가 아니며 세션 파일 내용 조작(LFI 등 결합)은 별도 취약점이 필요하다(보고서 §7 평가와 동일).

### S8. 보고서 주장 대조표 (정적)

| 보고서/PoC 주장 | 정적 판정 | 근거 |
|---|---|---|
| 구조체가 `zval*`를 장기 보관 | 확인 | php_session.h:136-137 |
| FILE_DATA에서 저장 포인터 직접 쓰기 | 확인 | session.c:3326-3327 |
| 업데이트마다 `Z_TRY_ADDREF`로 참조 유지 | 확인 | session.c:3189 |
| "세션 재초기화로 배열이 해제되어도 포인터 재사용" | **반박** | S3 — progress 소유 참조가 배열을 유지; 포인터 사용 시점에 해제된 메모리 없음 |
| 파싱 중 직렬화가 모듈 RINIT보다 먼저 실행 | 확인 | main.c:1871-1872 |
| BG(serialize)는 요청 간 잔류 가능 상태 | 확인(구조) | var.c:1326-1353, basic_functions.c:405-407 — 동적 검증 필요 |
| 인코딩 경로에 bailout 보호 없음 | 확인 | session.c:1061-1088 (decode의 zend_try와 대조) |
| tracked 할당기에서 memory_limit 우아한 강제 | 확인 | zend_alloc.c:2949-2961, 2963-2974 |
| multipart 폼 필드로 세션 ID 지정(쿠키 불필요) | 확인 | session.c:3246-3250, 3121-3137 |
| 8.5.4는 8.4.4와 해당 코드가 다르다 | 반박(해당 영역 동일) | S6 |

## 2. 동적 E2E 검증 (Phase 2)

실행 시각: 2026-10-21 21:53~21:56 KST · 하네스: `linux/probe.py`(HTTP E2E), `linux/gdb-probe.py`(GDB 상태 계측) · 증적: `var/linux-evidence/evidence/probe-*` (519개 파일, `evidence-manifest.sha256`에 SHA-256 기록)

### 2.1 실행 매트릭스 요약

| 프로파일 | 빌드 | 할당기 | 버퍼링 | 결과 | 워커 PID | ASAN |
|---|---|---|---|---|---|---|
| standard | 8.4.4-asan | tracked | off | completed | 517→517 | 0 |
| standard | 8.4.4-asan | system | off | completed | 577→577 | 0 |
| standard | 8.4.4-asan | zend | off | completed | 618→618 | 0 |
| standard | 8.4.4-asan | tracked | on | completed | 659→659 | 0 |
| standard | 8.4.4-asan | zend | on | completed | 700→700 | 0 |
| standard | 8.5.4-asan | tracked | off | completed | 741→741 | 0 |
| standard | 8.5.4-asan | zend | off | completed | 782→782 | 0 |
| lax(strict Off) | 8.4.4-asan | tracked | off | completed | 986→986 | 0 |
| oom (php 핸들러) | 8.4.4-asan | tracked | off | **워커 종료(70)** | 833→856 | 0 |
| oomps (php_serialize) | 8.4.4-asan | tracked | off | **워커 종료(70)** | 869→892 | 0 |
| oom (php 핸들러) | 8.5.4-asan | tracked | off | **워커 종료(70)** | 906→929 | 0 |
| oomps (php_serialize) | 8.5.4-asan | tracked | off | **워커 종료(70)** | 942→965 | 0 |
| GDB‑P8 | 8.4.4-asan | tracked | (CLI server) | **UAF 재현** | 프로세스 abort | **1** |
| GDB‑P8 | 8.5.4-asan | tracked | (CLI server) | **UAF 재현** | 프로세스 abort | **1** |
| GDB‑P8 | 8.4.4-asan | zend | (CLI server) | 잔류 없음·SIGSEGV | SIGSEGV | 0 |

### 2.2 P1/P2 — 도달성과 진행 상태 수명 주기 (확인, B)

8.4.4-asan/tracked/off에서 multipart에 `PHP_SESSION_UPLOAD_PROGRESS=p1`과 세션 쿠키를 넣어 256KB 파일을 16회 청크 전송하며 관측했다.

- 업로드 중 세션 파일에서 `upload_progress_p1` 키 확인, `bytes_processed`가 **15,594 → 261,306까지 16회 단조 증가**.
- 업로드 완료 응답 200 및 크기 일치, `session.upload_progress.cleanup=On`에 따라 **완료 후 키 제거**, 기존 `visits|i:1` 값 유지.
- 동일 FPM 워커(PID 517)가 전 구간 처리.

→ 애플리케이션 코드 실행 전 `php_session_rfc1867_callback()` 경로가 실제로 동작하며, 진행 데이터가 `$_SESSION`에 기록·정리된다. 보고서 §4의 “선택적 업로드 진행 콜백” 서술과 일치한다.

### 2.3 P3 — 클라이언트 중단 (확인, B)

192KB 전송 중 4청크 후 RST로 연결 종료:

- 중단 시점까지 진행 키가 세션 파일에 기록되었고, 중단 직후 **키가 정리**됨(cleanup 경로 동작).
- 워커 생존, `/health` 200, 이후 `/session` 방문 카운터 정상 증가.

### 2.4 P4 — 직렬화·업로드·중단 교차 10회 (확인, B)

동일 워커에서 세션 왕복 + 진행 업로드 + 3회 주기 중단을 반복: 방문 카운터 기대값과 완전 일치, 워커 재사용, ASAN 보고 없음. 정상 부하에서 상태 잔류 징후는 없었다.

### 2.5 P5 — 경계값·비정상 multipart (관측, B)

| 케이스 | HTTP | 워커 |
|---|---|---|
| 종료 boundary 누락 후 연결 종료 | 무응답(연결 종료) | 생존 |
| 중복 progress 필드(빈 값 포함) | 200 | 생존 |
| 200개 part | 400 | 생존 |
| 4KB filename | 200 | 생존 |
| 빈 필드명 part | 무응답 | 생존 |
| progress 값에 `|`, `"`, `;` 포함 | 200 | 생존 |

전 케이스에서 ASAN 오류·워커 재시작 없음. 한계: 마지막 케이스는 세션이 지정되지 않아 “세션 키 오염 → 다음 디코딩 실패”까지는 검증하지 못했다(후속 항목).

### 2.6 P7 — multipart 폼 필드 세션 ID (확인, B)

- `session.use_only_cookies=On` 상태에서 **쿠키 없이** 폼 필드 `PHPSESSID=<기존 sid>` + progress 필드 전송 → 해당 세션 파일에 진행 키가 기록됨(`form_field_sid_honored=true`). 코드 분석(S7)과 일치하며, ikow 주장·PR #22113의 현상이 재현된다.
- `use_strict_mode=Off`(lax 프로파일)에서는 **존재하지 않는 공격자 지정 이름의 세션 파일이 생성**됨(`sess_p7b8b29a2d0fe764fa2`, `file_created=true`). 관측 시점 크기는 0 — `cleanup=On`이 업로드 종료 시 진행 키를 지웠기 때문이다. `cleanup=Off`에서 내용이 잔류하는지는 후속 확인 항목.

### 2.7 P6/P8 — `BG(serialize)` 요청 간 잔류와 재사용

#### (a) FPM: 잔류가 다음 요청으로 넘어가지 않음 (확인, B)

`memory_limit=8M` + 3MB 위조 세션으로 파싱 중 메모리 한도 초과를 유도한 결과(4개 조합 모두 동일):

```text
PHP Fatal error: Allowed memory size of 8388608 bytes exhausted ...
WARNING: [pool lab] child 833 exited with code 70 after 0.480847 seconds from start
→ nginx 502, 워커 재기동(833→856), 다음 요청 200
```

**exit code 70 = FPM_EXIT_SOFTWARE_ERROR** — `php_request_startup()` 실패 시 FPM이 워커 프로세스를 종료한다. 따라서 BG(serialize) 잔류를 보유한 프로세스가 사라져 **FPM에서는 요청 간 재사용 경로가 성립하지 않는다.** 이것이 이번 CVE의 안전 근거는 아니며, SAPI 의존성의 증거다.

#### (b) CLI 내장 서버: 잔류 → 재사용 → ASAN UAF 재현 (확인, B)

GDB로 `BG(serialize)` 전이를 직접 기록했다(8.4.4-asan/tracked, 요청별 시작 시 level):

```text
req 0..4 (health, health, session, session, 소형 업로드): start level = 0,0,0,0,0
req 5 (3MB 세션 업로드):  SER_INIT level=0 → 초기화 성공
                          → encode 중 OOM bailout → SER_DESTROY 없음
                          → REQ_SHUTDOWN level=1, data=0x50600001d060  ← 잔류
req 6 (후속 업로드):      REQ_STARTUP level=1  ← 잔류 확인
                          SER_INIT level=1 → 해제된 컨텍스트 재사용
                          → ASAN heap-use-after-free → 프로세스 abort
```

ASAN 보고서(`asan.1087`)의 3개 스택이 가설과 정확히 일치한다:

| 구분 | 스택 |
|---|---|
| 할당 | `tracked_malloc` ← `_emalloc` ← **`php_var_serialize_init` (var.c:1330)** ← `ps_srlzr_encode_php` (session.c:1068) ← `php_session_encode` ← `php_session_flush` ← `php_session_rfc1867_update` (session.c:3192) |
| 해제 | `free` ← **`tracked_free_all` (zend_alloc.c:3019)** ← `zend_mm_shutdown` (2403) ← `shutdown_memory_manager` (2924) ← **`php_request_shutdown` (main.c:1979)** |
| 사용 | **`php_add_var_hash` (var.c:732, READ size 4)** ← `php_var_serialize_intern` (1060) ← `php_var_serialize` (1321) ← `ps_srlzr_encode_php` (1070) ← … ← `php_session_rfc1867_update` (3192) ← `php_session_rfc1867_callback` (3321) ← `rfc1867_post_handler` (973) ← `php_hash_environment` (788) ← **`php_request_startup` (main.c:1871)** |

8.5.4-asan/tracked에서 **동일 재현**(잔류 level=1, 재사용, ASAN 1건). 즉 이 경로는 8.4.4와 8.5.4에서 같게 동작하며, 소스 수정 없이 순정 빌드로 관측된다.

#### (c) zend 기본 할당기: 다른 지점에서 OOM, 잔류 없음 (미확정, C)

`USE_ZEND_ALLOC=1`에서는 같은 입력에서 OOM이 **decode 단계**(`zend_string.h:176`, 3,145,760바이트 할당)에서 먼저 발생해 `php_session_cancel_decode()`로 세션이 파괴되고, 직렬화 컨텍스트가 생성되지 않아 잔류가 없다(다음 요청 level=0). 이후 후속 요청 처리 중 **SIGSEGV**가 관측되었으나 ASAN 보고는 없었고 원인은 확정하지 못했다. 할당기 회계·청크 단위 차이로 OOM 지점이 달라진다는 사실 자체가 “조건 의존성”의 근거다.

#### (d) GDB 콜백 도달 증명 (확인, B)

`php_session_rfc1867_callback` 브레이크포인트에서 **이벤트 0(START)·1(FORMDATA)·2(FILE_START)·3(FILE_DATA)·4(FILE_END)·5(END)** 전부 관측됐다. 정상 업로드 경로가 콜백을 실제로 통과한다는 직접 증거다(검토 의견 P0 #1 보완).

### 2.8 검토 의견 반영 결과

| 검토 항목 | 이번 결과 |
|---|---|
| P0 콜백 도달성 | **충족** — P1/P2 관측 + GDB 이벤트 0~5 |
| P0 `BG(serialize)` 상태 관측 | **충족** — level/data/lock 요청 단계별 기록, 잔류·재사용 확인 |
| P0 HTTP 기반 패치 비교 | 하네스 준비 완료(`probe.py`), 공식 패치 후 동일 입력 재실행 단계로 연결 |
| P1 Apache mod_php | **미착수** — FPM이 startup 실패 시 워커를 종료(exit 70)하므로, 프로세스가 유지되는 Apache prefork가 결정적 비교 환경. Phase 4 선행 작업으로 등록 |
| P1 INI 변수화 | 부분 — `oom`(php)·`oomps`(php_serialize)·`lax`(strict Off) 추가 실행. `upload_progress.enabled=Off` 대조는 Phase 4 |
| P1 증적 해시 | **충족** — `var/linux-evidence/evidence-manifest.sha256` (519개) |
| Calif 정적 방법론 | 미착수 — S9 체크리스트로 계획에 등록 |
| PHP 공식 Fuzzer | 미착수 — Phase 4 이후 |

## 3. 통합 판정과 한계

### 3.1 주장별 최종 판정

| # | 주장/가설 | 정적 | 동적 | 종합 판정 |
|---|---|---|---|---|
| 1 | 업로드 진행 구조체가 `zval*`를 장기 보관 | 확인 | — | **사실 (A)** |
| 2 | FILE_DATA에서 저장 포인터로 직접 쓰기 | 확인 | — | **사실 (A)** |
| 3 | “세션 재초기화 → 배열 해제 → 포인터 재사용” UAF | 반박 | ASAN 오류 없음(전 조합) | **반박 (A/B)** — PoC A의 근본 원인 주장 성립 안 함 |
| 4 | 파싱 중 직렬화가 모듈 RINIT보다 먼저 실행 | 확인 | GDB로 확인 | **사실 (A/B)** |
| 5 | OOM bailout 시 `BG(serialize)` 잔류 | 확인(구조) | GDB level=1 확인 | **사실 (B)** — 단, FPM은 워커 종료로 소멸 |
| 6 | 잔류 컨텍스트 재사용 → heap-use-after-free | 확인(구조) | ASAN 8.4.4/8.5.4 재현 | **재현 (B)** — CLI server·ASAN·tracked·memory_limit 조건 |
| 7 | 위 UAF가 곧 무인증 RCE | — | 미시도·미검증 | **미확정 (C)** — 코드 실행 단계는 수행하지 않음 |
| 8 | multipart 폼 필드로 세션 ID 지정(쿠키 불필요) | 확인 | 재현(쿠키 없이) | **사실 (A/B)** |
| 9 | strict Off에서 공격자 지정 이름 세션 파일 생성 | 확인 | 파일 생성 확인(내용은 cleanup) | **부분 확인 (B)** |
| 10 | 8.5.4가 8.4.4와 다른 코드 | 반박 | 동일 재현 | **반박 (A/B)** — 해당 영역 동일 |

### 3.2 판정 수준 (검토 의견 §6 기준 적용)

- “HTTP 200 + 진행 상태 갱신” → **코드 경로 도달** 확인.
- “ASAN 동일 주소 해제 후 접근” → **해당 빌드·조건에서 메모리 오류 재현** 확인(8.4.4/8.5.4, CLI server, tracked, memory_limit).
- “수정되지 않은 정식 PHP에서 반복 재현” → CLI server 5/5, **Apache mod_php 3/3**, 두 SAPI·두 버전에서 재현. FPM은 워커 종료로 경로 자체가 소멸한다. 따라서 **“강하게 뒷받침” 단계로 한정**한다(SAPI 의존성 명시).
- “공식 패치 전 재현·후 소멸” → **미확인**(패치 미공개). Phase 4 항목.
- “공식 코드 변경·공지와 원인 일치” → **미확인**. 따라서 **CVE-2026-109618/109619의 근본 원인으로 확정하지 않는다.**

### 3.3 한계

1. 이번 UAF 재현은 **CLI 내장 서버 + ASAN + tracked 할당기 + `memory_limit` OOM** 조건이다. FPM은 `php_request_startup()` 실패 시 워커를 종료(exit 70)해 요청 간 잔류가 성립하지 않았고, Apache mod_php는 아직 구축하지 않았다. 배포 환경별 결론은 SAPI별로 달라질 수 있다.
2. OOM 지점은 할당기 회계 방식에 따라 decode/encode로 달라진다(zend에서는 decode). “어떤 조건에서 encode 도중 bailout이 나는가”가 잔류 성립의 핵심 변수다.
3. 어떤 단계에서도 코드 실행(RCE)·힙 그루밍·주소 조작을 시도하지 않았다. “UAF 재현”과 “익스플로잇 가능성”은 다른 문제이며, 이 보고서는 전자만 다룬다.
4. 이번 관측은 8.4.4/8.5.4 두 버전에 한정된다. 다른 버전·배포판 백포트·확장 구성은 별도 검증이 필요하다.
5. 세션 파일 위조는 랩 소유 디렉터리에서 수행한 실험 통제 수단이다. 실제 공격에서 세션 파일 내용을 통제하려면 별도 전제(파일 쓰기·LFI 등)가 필요하다.

### 3.4 패치 공개 후 즉시 할 일 (Phase 4)
1. php.net 보안 공지·GitHub 신규 태그로 CVE별 영향/수정 버전·공격 조건 확정.
2. 수정 버전을 동일 모드(asan/normal)로 빌드 → `probe.py` standard/lax/oom/oomps를 **동일 입력으로 재실행**해 전후 차이 비교(HTTP 응답·ASAN·워커 상태 3종).
3. `compare.py`로 공식 회귀 PHPT 비교(advisory.json에 공식 근거 기입).
4. Apache prefork + mod_php 프로파일 구축 후 P6/P8 재실행 — FPM에서 소멸한 잔류 경로가 프로세스 유지형 SAPI에서 어떻게 동작하는지 확인.
5. 공식 Diff에서 `main/main.c`(요청 시작 순서), `ext/standard/var.c`(serialize 상태), `ext/session/session.c`(rfc1867·flush) 변경 여부를 S1~S6과 대조.
6. `session.upload_progress.enabled=Off`·`cleanup=Off` 대조군, 세션 키 오염(2.5 한계) 항목 보완.

## 4. 추가 검증 (2026-10-21 22:30) — 방법론 통합·도구 검증

### 4.1 `session.upload_progress.enabled=Off` 대조 (P9, 확인 B)

동일 입력(64KB multipart + `PHP_SESSION_UPLOAD_PROGRESS`)에서 기능을 끄면:

- 업로드 자체는 200·정상 처리(`upload_still_works=true`).
- 업로드 중 세션 파일에 진행 키가 **전혀 나타나지 않음**(`progress_path_disabled=true`).

→ 2.2의 관측이 “업로드 진행 기능” 고유 경로임을 반증 가능한 형태로 확인했다. 즉 이 경로를 끄면 해당 관측은 사라지고, 다른 업로드 기능은 유지된다. (두 CVE 전체의 완화책이라는 주장과는 별개다.)

### 4.2 HTTP 전후 비교 도구 검증 (`linux/http-compare.py`)

동일 입력·동일 SAPI·동일 할당기 조건에서 두 빌드를 비교하고, 안정적 관측값만 비교 대상으로 삼는다(프로세스 ID·소요시간·바이트 수열 제외).

| 검증 | 구성 | 결과 |
|---|---|---|
| 음성 대조 | 8.4.4-asan vs 8.4.4-asan, progress-lifecycle | **identical**, 차이 0 |
| 양성 대조 | 동일 빌드 + after에 `upload_progress.enabled=Off` | **difference_observed** — `progress_key_mid_upload: true→false` |
| 교차 버전 | 8.4.4-asan vs 8.5.4-asan, oom-residue | **identical** — 양쪽 모두 `request_aborted_worker_exit`, `worker_exit_codes=[70]` |

→ 비교기가 ① 같은 것은 같다고, ② 실제 차이는 잡아낸다. 공식 패치가 나오면 `--before <취약> --after <수정>`으로 그대로 회귀 비교에 사용한다. 교차 버전 `identical`은 S6(해당 영역 코드 동일)과 일치한다.

### 4.3 판정 어휘 적용 현황 (계획 §9.5)

| 실행 | 상태 |
|---|---|
| 기존 environment matrix 18조합 | `environment_ready` |
| P1/P2/P3/P4/P7, GDB 이벤트 0~5 | `code_path_reached` |
| P8 tracked (8.4.4, 8.5.4) | `memory_error_observed` (ASAN 3종 스택) |
| P8 zend 후속 요청 SIGSEGV | `crash_observed` (원인 미확정) |
| oom/oomps 4조합 | `request_aborted_worker_exit` (exit 70) |
| http-compare 음성/교차 버전 | `identical` |
| http-compare 양성 대조 | `difference_observed` |
| Apache mod_php, WAF 파싱 차이, Fuzzer | `not_run` |
| 공식 패치 전후 | `not_run` → 패치 후 `regression_difference_observed` 목표 |

### 4.4 E2E의 범위 — 익스플로잇 미작성 (명시)

이 프로젝트의 E2E는 **입력→코드 경로→내부 상태→오류 증거→판정**까지이며, **무기화된 익스플로잇(힙 그루밍·주소 조작·RCE 체인)은 작성하지 않는다.** 이유:

1. 그것은 취약점 검증이 아니라 **모든 동일 버전 PHP 서버에 적용 가능한 범용 공격 도구** 제작이다.
2. 첨부 요청 문서도 “실제 취약점 발생 여부와 공격 가능성의 구분”, “메모리 오류 의심만으로 UAF 판정 금지”를 요구한다 — 즉 영향도 판정을 증거로 분리하라는 요구이지 익스플로잇 제작 요구가 아니다.
3. 보고서 §17.3도 “격리된 환경에서 무해한 재현 검증만” 수행하라고 명시한다.

대신 다음으로 “운영 영향” 질문에 답한다: 트리거 재현성·반복성, 영향 등급(요청 실패/워커 종료/프로세스 크래시), SAPI·버전·할당기·INI 조건 지도, 패치 전후 회귀, 탐지·완화 규칙 검증.

### 4.5 PoC 재현율과 조건 민감도 (2026-10-21 22:12 추가, 22:35 증거 연결 정정)

> **시각 정정:** 이전 판에 `23:10 추가`로 기재했으나 이는 오기다. 증적 타임스탬프 기준 실제 실행 시각은 22:10 KST이며, 최초 커밋 시각도 22:11 KST다. 이후 `00:12`로 적은 Apache 절도 실제로는 22:20 KST다.

`linux/poc-bgserialize.py`로 동일 시퀀스를 5회 반복(매회 새 프로세스)했다. **초기 집계 코드는 회차별 보고서를 구분하지 않고 첫 ASAN 파일을 재사용하는 결함이 있었다.** 수정 후 재실행(22:22 KST)에서 회차별로 새로 생성된 보고서만 판정에 사용했고, 프로세스 PID와 ASAN 파일 PID가 1:1로 일치했다.

| 회차 | 요청 A | OOM | 요청 B | 프로세스 PID | ASAN 파일 | 결과 |
|---|---|---|---|---|---|---|
| 1 | 500 | 확인 | 연결 리셋 | 412 | `asan.412` | uaf_reproduced |
| 2 | 500 | 확인 | 연결 리셋 | 414 | `asan.414` | uaf_reproduced |
| 3 | 500 | 확인 | 연결 리셋 | 416 | `asan.416` | uaf_reproduced |
| 4 | 500 | 확인 | 연결 리셋 | 418 | `asan.418` | uaf_reproduced |
| 5 | 500 | 확인 | 연결 리셋 | 420 | `asan.420` | uaf_reproduced |

**재현율 5/5 = 100%** (회차별 독립 보고서 5개, 모두 `php_add_var_hash` var.c:732). 자동 검증: `linux/verify-evidence.py` → `poc.status=passed, claimed=5, verified=5`.

> 이전 실행(13:09:43)은 디렉터리에 ASAN 보고서 5개가 실제로 존재했지만 집계 JSON은 0/5로 기록했다(같은 결함의 다른 증상). 해당 원본은 덮어쓰지 않고 보존했다.

#### 재현 조건의 민감도 — 실측으로 확인한 두 가지

1. **요청 A와 B 사이에 어떤 HTTP 요청도 보내면 안 된다.** 초기 PoC 러너는 A 후 생존 확인용 `/health`를 보냈는데, 그 요청이 `zend_activate_modules`에 도달하면서 `PHP_RINIT_FUNCTION(basic)`의 `memset(&BG(serialize), 0, ...)`(basic_functions.c:405-407)이 잔류를 지워 **0/5로 재현되지 않았다**. 확인 요청을 제거하자 5/5로 바뀌었다. 이는 “잔류가 존재하지만 다음 요청의 정상 초기화가 먼저 지운다”는 경계를 보여준다.
2. **OOM이 decode가 아니라 encode에서 나야 한다.** 프로세스 첫 요청에서 바로 OOM을 유도하면 `s_read`/decode 단계의 3MB 할당이 먼저 한도에 걸려(경고 없이 bailout) 직렬화 컨텍스트가 생성되지 않는다. 워밍업 후 요청에서 유도해야 encode의 `smart_str` 재할당(3,149,568바이트)이 한도에 걸리며 잔류가 생긴다.

#### 이 PoC가 증명하는 것 / 증명하지 않는 것

- **증명:** 순정 PHP 8.4.4(및 8.5.4)에서, 파싱 중 직렬화 컨텍스트가 요청 종료로 해제된 뒤 다음 요청의 파싱 단계에서 재사용되어 ASAN이 `heap-use-after-free`를 보고한다.
- **증명하지 않음:** 원격 무인증 단독 재현(위조 세션 파일에 대한 로컬 쓰기 필요), 임의 코드 실행, 다른 SAPI·버전·설정에서의 동일 동작.

### 4.6 Apache prefork + mod_php 결과 (2026-10-21 22:20 추가)

빌드: `linux/build-apache.sh 8.4.4` — `--with-apxs2=/usr/bin/apxs2`, `--enable-debug --enable-address-sanitizer`, `-O1`, 프리픽스 `install/8.4.4-apache`. httpd는 `LD_PRELOAD=libasan.so.8`, `ASAN_OPTIONS log_path`, `USE_ZEND_ALLOC=0`/`USE_TRACKED_ALLOC=1`로 **단일 프로세스(`-X`)** 실행, loopback 18088.

| 단계 | 관측 |
|---|---|
| 요청 A (3MB 세션 + progress) | 500, PHP Fatal “Allowed memory size ... 3149568 bytes” |
| 요청 A 직후 프로세스 | **생존** (FPM exit 70과 대조) |
| 요청 B (같은 프로세스) | 연결 리셋 = 프로세스 abort |
| ASAN | **3/3 보고서**(22:20), 추가 검증 2/2(22:24) — 각 회차 보고서가 해당 httpd PID와 일치 |

ASAN 스택도 CLI 서버와 동일하다: 할당 `ps_srlzr_encode_php` session.c:1068 ← `php_session_rfc1867_update` 3192 ← `php_request_startup` main.c:1871 / 사용 `php_var_serialize_intern` var.c:1060 ← `php_add_var_hash` 732 ← … ← main.c:1871.

#### SAPI별 비교 (이번 실측)

| SAPI | 요청 실패 후 프로세스 | 잔류 재사용 | 재현율 |
|---|---|---|---|
| CLI 내장 서버 | 유지 | 관측 | **5/5** |
| Apache mod_php (`-X`, prefork) | 유지 | 관측 | **3/3** |
| PHP-FPM | **종료(exit 70)** | 불가(잔류 소멸) | 0/4 |

→ 이 결함의 성립 여부는 “FPM인가”가 아니라 **SAPI가 요청 시작 실패 후 프로세스를 유지하는가**에 달려 있다. 배포 환경 판단 시 이 차이가 핵심이다.

### 4.7 판정 정확도 수정 (외부 검토 반영, 22:35)

| 지적 | 수정 내용 | 검증 |
|---|---|---|
| P0 회차별 ASAN 재사용 가능 | `snapshot_asan`/`wait_new_asan`으로 회차 시작 전 존재하던 보고서를 제외하고, **새로 생성된 보고서만** 사용. PID 일치 검사 | `verify-evidence.py` 5/5, pid 412·414·416·418·420 |
| P0 `gdb-probe.py` 고정 인덱스 `[4]` | 기록된 전이(serialize init 후 destroy 없음 + shutdown level>0)로 OOM 요청을 **식별**하고 다음 요청 인덱스를 계산 | `oom_request_index=5`, `reuse_request_index=6`, `residue_level=1` |
| P0 `probe-matrix.sh` 종료 코드 | `pipefail` + `PIPESTATUS[0]` 집계, 실패 시 비종료 코드로 종료 | `runs/failures` 요약 출력 |
| P1 `http-compare.py` `worker_reused` | PID 최초·최종 비교(`worker_pid_first/last`, `worker_restarted`)로 교체 | 음성 대조 `identical` 재확인 |
| P1 비교 판정 남용 | `--advisory` 없으면 `difference_observed`, 공식 영향/수정 버전이 일치할 때만 `regression_difference_observed` | 음성/양성 대조 |
| P1 PoC 워밍업 세션 미유지 | 쿠키 자를 사용해 동일 세션 2회 왕복, 방문 카운터 증가 검증(`session_roundtrip_ok`) | 각 회차 기록 |
| P1 매니페스트 BOM | UTF-8(BOM 없음)으로 재생성, 검증기가 BOM을 오류로 판정 | 첫 바이트 `00 62`, 1044개 해시 일치 |
| P1 원본 증적 부재 | `docs/evidence-manifest-20261021.sha256`(1044개) + `verify-evidence.py`로 재검증 절차 제공 | 전체 해시 검사 통과 |

### 4.8 미구현·미검증 목록 (과장 금지)

| 항목 | 상태 | 사유 |
|---|---|---|
| Apache prefork + mod_php 프로파일 | **완료** — 빌드·기동·A/B 재현 3/3 (§4.6) | — |
| WAF vs PHP 파싱 차이 랩(WAFFLED) | `not_run` | 로컬 WAF 구성 필요 |
| FlowFusion/공식 Fuzzer 통합 | `not_run` | 별도 빌드·Corpus |
| ZendDiff식 JIT/non-JIT 비교 | `not_run` | JIT 빌드 필요 |
| `cleanup=Off` 세션 파일 내용 잔류 | `not_run` | 후속 1회 실행으로 확인 가능 |
| 공식 패치 전후 비교 | `not_run` | 패치 미공개(23:00 KST 예정) |

