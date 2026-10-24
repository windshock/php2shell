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
- `use_strict_mode=Off`(lax 프로파일)에서는 **존재하지 않는 공격자 지정 이름의 세션 파일이 생성**됨(`sess_p7b8b29a2d0fe764fa2`, `file_created=true`). 관측 시점 크기는 0 — `cleanup=On`이 업로드 종료 시 진행 키를 지웠기 때문이다. `cleanup=Off`에서 내용이 잔류하는 것은 별도로 확인했다(§4.9b).

### 2.7 P6/P8 — `BG(serialize)` 요청 간 잔류와 재사용

#### (a) FPM: 잔류가 다음 요청으로 넘어가지 않음 (확인, B)

`memory_limit=8M` + 3MB 위조 세션으로 파싱 중 메모리 한도 초과를 유도한 결과(4개 조합 모두 동일):

```text
PHP Fatal error: Allowed memory size of 8388608 bytes exhausted ...
WARNING: [pool lab] child 833 exited with code 70 after 0.480847 seconds from start
→ nginx 502, 워커 재기동(833→856), 다음 요청 200
```

**exit code 70 = FPM_EXIT_SOFTWARE_ERROR** — `php_request_startup()` 실패 시 FPM이 워커 프로세스를 종료한다. 따라서 BG(serialize) 잔류를 보유한 프로세스가 사라져 **이번에 시험한 요청 초기화 실패 시퀀스에서는** 요청 간 재사용이 성립하지 않는다. RINIT **이후** fatal 경로는 별개이며(§7.1 Path C), 이것이 이번 CVE의 안전 근거는 아니다.

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
- “수정되지 않은 정식 PHP에서 반복 재현” → CLI server 5/5, **Apache mod_php 3/3**, 두 SAPI·두 버전에서 재현. FPM은 **startup 실패 시퀀스에서** 워커 종료로 경로가 소멸한다(RINIT 이후 fatal 경로는 §7.1 Path C로 별도). 따라서 **“강하게 뒷받침” 단계로 한정**한다(SAPI 의존성 명시).
- “공식 패치 전 재현·후 소멸” → **미확인**(패치 미공개). Phase 4 항목.
- “공식 코드 변경·공지와 원인 일치” → **미확인**. 따라서 **CVE-2026-109618/109619의 근본 원인으로 확정하지 않는다.**

### 3.3 한계

1. 이번 UAF 재현은 **CLI 내장 서버 + ASAN + tracked 할당기 + `memory_limit` OOM** 조건이다. FPM은 `php_request_startup()` 실패 시 워커를 종료(exit 70)해 **이 시퀀스에서는** 요청 간 잔류가 이어지지 않았다. 배포 환경별 결론은 SAPI별로 달라질 수 있다.
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
| PHP-FPM | **종료(exit 70)** | 불가(이 시퀀스 한정) | 0/4 |

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
| P1 매니페스트 BOM | UTF-8(BOM 없음)으로 재생성, 검증기가 BOM을 오류로 판정 | 첫 바이트 `00 62`, 1,992개 해시 일치(최신 기준) |
| P1 원본 증적 부재 | `docs/evidence-manifest-20261021.sha256` + `verify-evidence.py`로 재검증 절차 제공 | 전체 해시 검사 통과 |

### 4.8 `BG(unserialize)` 재현과 multipart 종료 대조 (2026-10-21 22:55 추가)

#### (a) Bug U — `BG(unserialize)` 요청 간 UAF: **재현**

`linux/gdb-unserialize.py` (CLI 내장 서버, ASAN, tracked, `memory_limit=5M`, 3MB 위조 세션). 5M는 `s_read`(약 3MB)는 통과시키고 decode의 문자열 할당(3MB)이 한도를 넘도록 고른 값이다.

| 단계 | 관측 |
|---|---|
| 요청 A | 500, `Allowed memory size ... exhausted`, `Failed to decode session object` |
| A 종료 시 | `BG(unserialize).level = 1` (DESTROY 생략) |
| 요청 B (동일 프로세스) | 연결 리셋 = 프로세스 abort |
| ASAN | 1건, `heap-use-after-free` |
| GDB 인덱스 | `oom_request_index=3`, `reuse_request_index=4`, `request_levels=[0,0,0,0,1]` |

ASAN 스택:

| 구분 | 스택 |
|---|---|
| 사용 | **`tmp_var` (var_unserializer.re:166)** ← `ps_srlzr_decode_php` (session.c:1120) ← `php_session_decode` (279) ← `php_session_rfc1867_update` (3182) |
| 할당 | **`php_var_unserialize_init` (var_unserializer.re:64)** ← `ps_srlzr_decode_php` (1103) ← `php_session_decode` (279) |

→ Bug S(`BG(serialize)`)와 **같은 계열의 결함이 decode 경로에도 존재**한다. 두 후보 모두 순정 8.4.4에서 재현되며, 서로 다른 직렬화 상태를 사용한다.

#### (b) multipart 부품 수 제한과 END/cleanup — 19h 주장 **반박**

`max_multipart_body_parts=3`에서 progress 필드 → 파일 → 추가 필드 10개를 보내 한도를 초과시켰다.

- 관측: `Multipart body parts limit exceeded` 경고 발생, HTTP 200, **진행 키가 세션에서 제거됨**(`key_removed=true`).
- 코드 근거: `--body_parts_cnt < 0` → `goto fileupload_done`(rfc1867.c:795-797)이고, `fileupload_done` 라벨이 `MULTIPART_EVENT_END`를 호출한다(1267-1272). 즉 END는 생략되지 않으며 cleanup도 실행된다.
- 판정: “부품 수 제한 초과로 END가 생략되어 세션 데이터가 보존된다”는 설명은 8.4.4 원본에서 성립하지 않는다. 다른 원인으로 잔류가 관측됐다면 세션 저장 실패 등 별도 경로를 조사해야 한다.

### 4.9 HTTP-only Arm과 cleanup=Off 대조 (2026-10-21 22:36 추가)

#### (a) HTTP 입력만으로 parse-time OOM 도달? — **음성**

위조 세션 없이, 901개 필드(각 4KB, 합계 약 3.6MB) + progress 필드 + 1KB 파일을 FPM(`memory_limit=8M`, `post_max_size=4M`)에 전송했다.

- 응답 200, `Allowed memory size ... exhausted` **없음**, 워커 생존(PID 440).
- 해석: 이 입력 형태만으로는 파서 자체 할당이 한도에 도달하지 않았다. Calif는 **`filename=""` 빈 업로드 + 중첩 필드명**으로 본문 8MiB 미만에서 128MiB 힙을 소진했다고 보고했으므로(§7.2), 이 음성 결과를 일반화할 수 없다.
- 구조적 요점: OOM이 `php_var_serialize`/`php_var_unserialize`의 INIT→DESTROY 윈도우 **밖**에서 발생하면 잔류가 만들어지지 않는다. 따라서 “OOM 발생”과 “잔류 재사용”은 별개 조건이다.

#### (b) `cleanup=Off`에서 진행 데이터 잔류 — **확인**

동일 업로드(64KB)에서 `session.upload_progress.cleanup=Off`:

- 완료 후에도 `upload_progress_co1` 키 유지, `bytes_processed=65805`, `done=true`.
- 기본값(On)에서는 완료 시 키가 제거된다(§2.2와 대조).

### 4.10 WAF 파싱 대조 (WAFFLED 방식, 2026-10-21 22:37 추가)

환경: Apache 2.4.58 + mod_php 8.4.4 + **ModSecurity 2.9.7**, loopback 18090, 규칙:

```apache
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" "id:1001,phase:2,deny,status:403"
```

PHP 측은 `cleanup=Off`로 진행 키를 유지해, 요청 후 세션 파일에서 `upload_progress_<value>` 존재 여부로 **PHP 실제 도달**을 판정했다.

| 변형 (Content-Disposition) | HTTP | PHP 도달 | 판정 |
|---|---|---|---|
| `name="PHP_SESSION_UPLOAD_PROGRESS"` (기준) | 403 | 아니오 | WAF 차단 |
| `name=PHP_SESSION_UPLOAD_PROGRESS` (비인용) | 403 | 아니오 | WAF 차단 |
| `name = "…"` (공백) | 403 | 아니오 | WAF 차단 |
| `filename="x"; name="…"` (순서) | 200 | 아니오 | PHP가 진행 필드로 인식 안 함 |
| `name="php_session_upload_progress"` (소문자) | 200 | 아니오 | PHP는 대소문자 구분 |
| **`name="foo"; name="…"` (중복)** | **200** | **예** | **규칙 누락 — PHP는 처리** |
| `name*=UTF-8''…` (RFC2231) | 400 | 아니오 | 양쪽 미처리 |
| `name="…"\t` (탭) | 403 | 아니오 | WAF 차단 |
| `name="…";` (세미콜론) | 403 | 아니오 | WAF 차단 |
| **`foo="bar"; name="…"` (추가 파라미터)** | **200** | **예** | **규칙 누락 — PHP는 처리** |

**요약:** 10개 중 5개 차단, **2개는 WAF를 통과하면서 PHP는 진행 필드로 처리**했다(`passed_and_reached`).

해석:

1. 필드 이름 문자열 매칭(`ARGS_NAMES @streq`) 규칙은 **파라미터 순서·중복**에 취약하다. ModSecurity의 multipart 이름 해석과 PHP rfc1867의 해석이 다르기 때문에, 같은 요청을 한쪽은 일반 필드로, 다른 쪽은 진행 필드로 본다.
2. 따라서 이런 유형의 WAF 규칙을 “PHP2Shell 가상패치”라고 부를 수 없다(보고서 §13.3의 경고와 일치).
3. `filename_first`는 양쪽 모두 진행 필드로 보지 않았으므로 차단 누락이 아니라 **PHP 쪽 미도달**이다. 판정을 “WAF 차단/허용”과 “PHP 도달”로 분리한 이유다.

한계: 단일 WAF 버전·단일 규칙·로컬 환경이다. 상용 WAF/CRS의 정규화·디코딩 단계는 별도 검증이 필요하다.

### 4.11 공식 Fuzzer 스모크 (2026-10-21 22:47 추가)

`linux/build-fuzzer.sh`로 순정 8.4.4에 fuzzing SAPI를 빌드했다(`--enable-fuzzer --with-pic --enable-debug-assertions --enable-address-sanitizer`, clang). 산출물 `php-fuzz-unserialize`(59MB)로 60초 스모크:

| 항목 | 결과 |
|---|---|
| 시드 Corpus | 19개 (`sapi/fuzzer/corpus/unserialize`) |
| 실행 횟수 | **485,434** (약 7,957 exec/s) |
| 신규 단위 | 2,893 |
| peak RSS | 149MB |
| crash artifact | **0** |
| 종료 코드 | 0 |

한계: `generate_unserialize_dict.php`가 최소 빌드에서 **빈 사전**을 출력해(클래스 목록 비어 있음) 사전 없이 실행했다. 60초 스모크는 “크래시가 없었다”는 관측일 뿐 취약점 부재의 증거가 아니며, FlowFusion의 데이터흐름 변형·테스트 축소는 통합하지 않았다.

**교차 버전 확인(8.5.4):** `parts`·`cleanup`·`arm` 프로파일을 8.5.4에서도 실행해 동일 결과를 얻었다 — 부품 한도 초과 시 END·cleanup 실행(`key_removed=true`), `cleanup=Off`에서 키·done 유지, HTTP-only 입력에서 OOM 없음.

### 4.12 JIT/non-JIT 차등 (ZendDiff 방식, 22:51 추가)

`linux/build-jit.sh`로 opcache 포함 8.4.4를 빌드하고, 20,000회 `serialize`/`unserialize` + 세션 encode/decode 스크립트를 `opcache.jit=off|tracing|function`으로 실행했다.

| 설정 | 출력 | exit | 시간 |
|---|---|---|---|
| off | 기준 | 0 | 34ms |
| tracing | **동일** | 0 | 29ms |
| function | **동일** | 0 | 30ms |

해석: 출력 수준 차등에서는 세 모드가 완전히 일치한다. 단, 이는 ZendDiff의 **내부 상태 프로빙**이 아니라 출력·종료코드 비교이며, 이번 PHP2Shell 경로는 사용자 코드 실행 이전의 파싱 단계(C 코드)라 JIT 영향과 무관하다는 전제의 대조군이다.

### 4.13 미구현·미검증 목록 (과장 금지)

| 항목 | 상태 | 사유 |
|---|---|---|
| Apache prefork + mod_php 프로파일 | **완료** — 빌드·기동·A/B 재현 3/3 (§4.6) | — |
| WAF vs PHP 파싱 차이 랩(WAFFLED) | **완료** — Apache+ModSecurity 2.9.7, 10변형 중 2건 규칙 누락(§4.10) |
| FlowFusion/공식 Fuzzer 통합 | **부분 완료** — 공식 `php-fuzz-unserialize` 빌드·60초 스모크(485,434회, crash 0). FlowFusion 변형·축소 미통합(§4.11) |
| ZendDiff식 JIT/non-JIT 비교 | **부분 완료** — 출력 수준 3모드 동일(§4.12), 내부 상태 프로빙 미구현 | `linux/jit-compare.sh` |
| `cleanup=Off` 세션 파일 내용 잔류 | **완료** — 키·done 유지 시연(§4.9b) | `probe.py --profile cleanup` |
| 공식 패치 전후 비교 | **완료** — 8.4.27에서 PoC 0/5, ASAN 0, HTTP identical (§5) | `linux/phase4.sh` |
| HTTP 입력만으로 OOM(Arm 단계) | **측정 완료(음성)** | 901필드×4KB에서 OOM 없음(§4.9a); 더 큰 body·다른 SAPI는 미실시 |

## 5. Phase 4 — 공식 패치(8.4.27) 전후 비교 (2026-10-21 23:15)

### 5.1 공식 발표 사실

PHP 보안팀은 2026-10-21 **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**를 공개하며 두 Critical 취약점을 명시했다(공식 공지 인용).

- **CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) — RCE via OOM corruption**: “out-of-memory handling can interrupt PHP while internal request data is only partially initialized. Request cleanup may then treat the invalid data as valid.”
- **CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) — RCE via stale global state**: “request-owned internal state can survive after its backing memory has been freed. A later request handled by the same worker may use that stale state before normal initialization resets it.”
- 위험도는 **mod_php에서 최고**로 표시되며, “unauthenticated request can trigger the attack before any application code runs”라고 명시했다.

이는 이 보고서가 독립적으로 재현한 두 경로와 정확히 대응한다.

| 우리 분석 | 공식 CVE |
|---|---|
| Bug S — `BG(serialize)` 잔류·재사용(§2.7, §4.5) | **CVE-2026-109619** (stale global state) |
| Bug U — `BG(unserialize)` 잔류·재사용(§4.8a) | **CVE-2026-109619** (동일 계열) |
| 파싱 중 OOM bailout으로 직렬화 컨텍스트 정리 누락 — **109619의 전제 조건** | **CVE-2026-109619** (109618 아님) |
| 부분 초기화된 HashTable Bucket이 종료에서 소비(§7 Path A) | **CVE-2026-109618** — Calif 확인, **자체 미재현** |

> **정정:** 이전 판은 “OOM bailout → 컨텍스트 정리 누락”을 109618로 표기했으나 잘못이다. 109618의 대표 원인은 **`_zend_hash_str_add_or_update_i`의 count-before-key-allocation**으로 생기는 부분 초기화 Bucket이며(mod_php 종료에서 소비), 우리가 재현한 직렬화 상태 잔류는 **109619**다.

### 5.2 공식 Diff가 가리키는 원인 (8.4.4 → 8.4.27)

`linux/patch-diff.sh`로 9개 파일을 비교했다(증적: `evidence/patch-diff-8.4.4-8.4.27.txt`). 변경 hunk 수: `Zend/zend_alloc.c` 44, `main/rfc1867.c` 34, `var_unserializer.re` 22, `ext/session/session.c` 21, `main/main.c` 14, `basic_functions.c` 14, `var.c` 13, `php_variables.c` 10, `php_session.h` 1.

핵심 변경 1 — **BG 상태 리셋을 요청 시작 직후로 이동**:

```c
/* Called from php_request_startup(), before any request data is processed. */
PHPAPI void php_basic_early_rinit(void)
{
    /* The session upload progress handler (un)serializes the session and
     * registers the session id with the URL rewriter from
     * php_hash_environment(), before RINIT. */
    BG(serialize_lock) = 0;
    memset(&BG(serialize), 0, sizeof(BG(serialize)));
    memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
    php_url_scanner_early_rinit();
}
```

이 주석은 이 보고서 §2.7·§4.8의 분석(“파싱 중 직렬화가 RINIT보다 먼저 실행되어 이전 요청의 잔류 상태를 본다”)과 **문장 단위로 일치**한다.

핵심 변경 2 — **rfc1867 경로의 직렬화 범위 제한**: `PS(in_rfc1867_update)` 플래그를 추가하고, 업로드 진행 콜백이 (un)serialize하는 동안 `php_var_unserialize_set_incomplete_classes_only()` / `php_var_serialize_set_incomplete_classes_only()`를 켜서 **미완성 클래스만** 다루도록 했다(`session.c`, `var.c`·`var_unserializer.re` 신규 함수). 즉 파싱 단계에서 사용자 객체·소멸자 경로가 개입하지 못하게 했다.

핵심 변경 3 — **OOM 처리 경로**: `zend_alloc.c`(44 hunk), `main.c`, `rfc1867.c`가 함께 변경되어, 메모리 한도 초과로 요청 초기화가 중단될 때의 정리 동작이 바뀌었다(CVE-2026-109618 대응으로 해석).

### 5.3 8.4.27에서 동일 입력 재실행 결과

`linux/phase4.sh 8.4.27 var/advisory-8.4.27.json` (공식 advisory 검증 통과, 빌드 재사용):

| 단계 | 8.4.4 (취약) | 8.4.27 (수정) |
|---|---|---|
| PoC `poc-bgserialize.py` | 5/5 UAF | **0/5, ASAN 보고 없음** |
| GDB serialize 잔류 | `level=1` → 재사용 → UAF | **잔류 없음**(levels 전부 0) |
| GDB unserialize 잔류 | `level=1` → 재사용 → UAF | **잔류 없음** |
| http-compare progress | 기준 | `identical` |
| http-compare oom-residue | 워커 exit 70, 502 | `identical` (동일 동작) |
| verify-evidence | passed | passed |

**최종 판정: `no_difference_observed` + `patch_effect_signal = "memory error no longer reproduced in this lab (poc 0/5, no ASAN residue)"`.**

### 5.4 판정 사다리 적용

| 조건 | 판정 | 근거 |
|---|---|---|
| 공식 CVE 영향·수정 버전 확인 | 충족 | 8.4.27 공지·GHSA |
| 공식 패치가 원인 코드를 수정 | 충족 | `php_basic_early_rinit()` + `in_rfc1867_update` 제한 |
| 동일 입력에서 오류 소멸 | 충족 | PoC 0/5, ASAN 0, 잔류 0 |
| **`patch_effect_confirmed`** | **성립(랩 범위)** | 위 3개 충족. 단 “우리 PoC 조건에서”라는 한정 |
| `root_cause_confirmed` (CVE-2026-109619) | **성립** | 공지 문구 + Diff + 재현·소멸이 동일 메커니즘 지목 |
| `root_cause_confirmed` (CVE-2026-109618) | 부분 | OOM 처리 변경은 확인했으나 109618 고유의 손상 경로를 별도 재현하지 않음 |

### 5.5 한계 (과장 금지)

1. 이번 확인은 **우리 PoC 조건**(CLI/Apache, ASAN+tracked, 세션 파일 위조, OOM 유도)에서의 소멸이다. 공지가 말한 “무인증 원격 RCE”를 재현하거나 검증한 것이 아니다.
2. 8.4.27 빌드는 `--disable-all` 최소 구성이며, 배포판 패키지·다른 확장 구성은 별도 확인이 필요하다.
3. `patch_effect_confirmed`는 랩 판정이고, 운영 배포 판정은 공식 패키지·회귀 테스트·벤더 백포트 확인으로 별도 수행해야 한다.
4. 공식 완화책(공지): 109618 — `memory_limit=-1`, 낮은 `post_max_size`, 프록시/컨테이너 수준 입력 한도; 109619 — `session.upload_progress.enabled=0` + 전 워커 재시작, PHP 8.5는 `fatal_error_backtraces=0`, 초기화 전 진단을 내는 잘못된 설정 제거. 이는 우리 실험(업로드 진행 경로·OOM 조건)과 방향이 일치한다.


## 6. P0/P1 잔여 항목 (커밋 b56e745, 2026-10-21)

### 6.1 8.5.12 교차 검증 — 완료

`phase4.sh 8.5.12`(advisory: 8.5.4 → 8.5.12): **PoC 0/5, ASAN 0, 잔류 0, http-compare identical** → `no_difference_observed` + `patch_effect_signal`. 8.4 계열과 동일한 결과다.

### 6.2 CVE-2026-109618 고유 손상 경로 — 방향 확인, 손상 미재현

공식 Diff의 109618 대응: `main.c`에 `memory_hard_limit_percent`(기본 200% 또는 +1GB)를 신설해 **OOM 후 정리용 여유**를 확보하고, `php_variables.c`·`rfc1867.c`에 `ZEND_HAS_OOM()` 조기 종료를 추가해 “부분 초기화된 요청 데이터를 유효한 것으로 정리”하지 않게 했다. `array_init_singleton()`도 해시 할당을 줄인다.

프로브(P14 `oomparse`): 중첩 배열 파라미터 30,000개(본문 약 0.6MB, 메모리 증가는 배열 오버헤드)로 파싱 중 OOM 유도.

| 빌드 | 응답 | 파싱 중 OOM | ASAN | 워커 |
|---|---|---|---|---|
| 8.4.4 | 502 | **예** | 0 | 생존(재기동) |
| 8.4.27 | 400 | 아니오(fatal 없음) | 0 | 생존 |

→ **조건과 처리 차이는 재현**했으나(수정 빌드는 조기 종료로 fatal 없음), 109618 고유의 메모리 손상은 관측되지 않았다. **고유 경로 재현은 미완**으로 남긴다.

**SAPI·전달 형태 주의:** Calif가 지목한 대표 소비 지점은 **Apache mod_php**이고, 이 실험은 **FPM**에서 수행됐다. 또한 OOM 전달은 “일반 필드 다수” 방식이었으며, Calif의 `filename=""` 빈 업로드 + 중첩 필드명(본문 8MiB 미만으로 128MiB 소진), chunked/lengthless, 압축 해제 불일치 기법은 **미시험**이다(§7.2).

### 6.3 CVE-2026-109619 “다른 변형” 후보 — 정적 조사

시작 단계(파싱, RINIT 이전)에서 (un)serialize에 도달하는 호출지를 조사했다(`linux/serialize-sites.sh`).

- `php_var_serialize`/`unserialize` 호출은 session.c 외에 gmp·sysvshm·phar·spl에도 있으나, 모두 **사용자 코드·객체를 통한 실행**이 필요해 파싱 단계에서 도달하지 않는다.
- 파싱 단계 도달 가능: `ext/session/session.c`(rfc1867 업로드 진행) — 이번에 재현한 경로.
- 공식 패치가 추가로 `php_url_scanner_early_rinit()`을 호출한다 → **URL rewriter(trans_sid) 상태**도 요청 시작에 초기화가 필요한 상태류로 취급됨(직렬화는 아님).
- PHP 8.5에는 `fatal_error_backtraces`(zend.c)가 있고 공지가 8.5 완화책으로 `fatal_error_backtraces=0`을 제시 → **fatal 백트레이스 경로**가 별도 변형 후보.

**판정:** 시작 단계 (un)serialize 경로는 세션 업로드 진행이 유일하게 확인됐고, 나머지는 “직렬화가 아닌 요청 시작 상태”(url_scanner) 또는 8.5 전용 fatal 경로다. trans_sid·fatal 주입 실험은 **미실시**.

### 6.4 탐지 룰 — 구축·부분 검증

`linux/detect-rules/`에 ModSecurity 룰과 Sigma 룰을 추가했다.

| 룰셋 | 차단 | PHP 도달 | 비고 |
|---|---|---|---|
| 단순 `ARGS_NAMES @streq`(기존) | 5/10 | 2 | 기준선 |
| `ARGS_NAMES @streq` + `FILES_NAMES @streq` | 6/10 | 2 | `filename_first` 차단 추가. 단 이 변형은 PHP 미도달 → **실질 위험 감소 0** |
| `MULTIPART_PART_HEADERS`(@contains) | 실효 없음 | 2 | 2.9.7에서 중복/추가 파라미터 미탐(실측) |
| `REQUEST_BODY` 체인 | 실효 없음 | 2 | multipart 처리 후 본문 미노출 |

- Sigma 3종(실험적): ① 중복·추가 파라미터를 가진 업로드 진행 필드, ② 파싱 중 OOM fatal, ③ multipart 직후 FPM 워커 종료(신호/exit 70). **SIEM 실행 검증은 미실시**.
- 결론: 이름 기반 룰은 6/10이 한계다. 나머지는 **원문 바이트를 보는 프록시/게이트웨이** 또는 `session.upload_progress.enabled=0`로 닫아야 한다.

### 6.5 검토 반영 — 판정 정확도 수정

| 지적 | 수정 | 검증 |
|---|---|---|
| Sigma `id`가 UUID가 아님 | UUIDv4로 교체 | `linux/validate-rules.py` **PASS** |
| Sigma 목록이 OR로 평가됨 | 필드를 매핑으로 바꿔 AND 강제, 조건을 `selection_a and (b or c)`로 명시 | 구조 검증 PASS (sigma-cli·SIEM 미실행) |
| 워커 종료 규칙이 상관분석을 주장 | 규칙 3·4로 분리하고 “SIEM에서 join” 명시 | 문서화 |
| `phase4.sh`가 inconclusive를 성공 처리 | 프로브 rc 전체 집계 + `inconclusive` 전파 + 종료 코드 0/2/1 | **음성 대조 exit=2** (`PHASE4_INCONCLUSIVE`) |
| WAF “개선”이 실질 위험을 줄이지 않음 | `@contains`→`@streq`(오탐 축소), README에 “통제 아님·위험 감소 0” 명시 | 6/10 차단, **PHP 도달 2건 유지** |
| P14가 워커 생존을 오판 | PID before/after·재기동·ASAN 유형·응답 스니펫 기록 | 8.4.4: 502, PID 413→436(재기동) / 8.4.27: 400, PID 443→443 |
| 문서 시각·커밋 불일치 | §6 머리글을 커밋 기준으로, Executive Summary는 해시 대신 매니페스트 참조 | — |

**남은 한계:** Sigma 규칙은 구조 검증만 거쳤고 SIEM 변환·실행은 미실시다. ModSecurity 룰은 여전히 검증된 우회 2건을 막지 못하므로 **운영 차단 통제로 배포하면 안 된다**.

### 6.6 2차 검토 반영 — 증적 귀속·PoC 판정 (2026-10-21, 커밋 기준)

| 지적 | 수정 | 검증 |
|---|---|---|
| PoC 결과가 최종 성공 판정에 미반영 | `poc_valid`(이번 실행 결과 JSON 존재 + 5회 + 회차별 `result` 필드)를 `harness_ok`에 포함. PoC **실행 실패**와 **미재현**을 구분 | 8.4.27 실행: `poc_valid=true`, exit 0 / PoC 산출물이 없으면 inconclusive |
| `verify-evidence`가 이전 증적을 검사 | `--since <epoch>`·`--root <라이브 경로>`·`--skip-manifest` 추가. Phase 4는 **이번 실행 이후 생성된** PoC/GDB 증적만 인정 | `--since` 미래값 → `failed`(exit 1), 정상 실행 → `passed` |
| Phase 4 증적 경로 미연결 | 원본 증적 루트(`/home/phplab/php-lab/evidence`)를 직접 검사하고, 내보낸 사본과 분리 | 정상 exit 0 / 음성 대조 exit 2 재확인 |
| Sigma 규칙 4의 `.php` 경로 필터 | 경로 조건 제거(모든 multipart POST), 프론트 컨트롤러 재작성·로그 본문 PII 주의 명시 | 구조 검증 PASS |
| `validate-rules.py`가 구조 검사만 수행 | `sigma-cli` 변환을 시도했으나 기본 이미지에 `pip`가 없어 설치 실패 → **구조 검증만** 수행함을 명시 | 미완(한계로 기록) |
| ModSecurity 파일이 실제 `deny` 동작 | `modsecurity-php2shell.example.conf`로 개칭, “운영 적용 금지” 헤더 추가, 랩 기본 경로 갱신 | `waf-compare` 6/10·PHP 도달 2건 유지 |
| 문서 증적 개수 불일치 | 하드코딩 제거(매니페스트 참조) | — |

**남은 한계:** Sigma의 SIEM 변환·실행 검증과 109618 고유 손상 경로 재현은 여전히 미완이다.

## 7. Calif 연구 대조와 3경로 재분류 (2026-10-22)

원문: [calif.io/php2shell](https://calif.io/php2shell/) — PHP 2004/2020/2024 계보, 2026-08 발견, 10월 릴리스. Calif·OpenAI·Wiz 공동 연구.

### 7.1 Calif가 정의한 세 중단 지점

| 경로 | 메커니즘(원문 요약) | SAPI | 자체 상태 |
|---|---|---|---|
| **A. 부분 초기화 HashTable** (109618) | `_zend_hash_str_add_or_update_i`가 `nNumUsed++`/`nNumOfElements++` 후 `p->key = zend_string_init(...)`에서 fatal → Bucket은 teardown에 보이지만 key/val 미초기화. mod_php는 startup 실패 후에도 `php_request_shutdown()`이 돌아 malformed `$_POST/$_FILES`를 파괴 | mod_php (PHP ≥ 7.3) | **미재현** — P14는 **FPM**에서 시도해 소비 지점을 관찰하지 못했음 |
| **B. Session 전역 상태 잔류** (109619) | 업로드 진행이 파싱 중 `php_rinit_session(0)`으로 `PS(id)`·`PS(http_session_vars)`를 요청 힙에 묶음 → 이후 fatal로 END 콜백·Session RSHUTDOWN 생략(`PG(modules_activated)=0`) → 힙 해제, **Apache 워커 생존** → 다음 multipart(파일 파트 없음)의 END cleanup이 댕글링 PS를 소비 | mod_php (PHP ≥ 5.4) | **미검증** — 우리는 BG 상태만 계측 |
| **C. `BG(unserialize)` post-RINIT** (109619) | RINIT **이후** 애플리케이션 실행 중 unserialize 도중 fatal이 나면 컨텍스트가 남고, **워커가 살아남아**(FPM·mod_php 공통, 앱 의존 — §7.5 정정) 다음 요청이 재사용 | PHP-FPM·mod_php (앱 의존) | **부분** — 우리는 **pre-RINIT**(파싱 중 decode) OOM으로만 재현. post-RINIT 생산자/소비자 경로는 미검증(FPM이 자체 미커버 SAPI라 P17 대상) |

### 7.2 OOM 전달 기법 — 우리 P12 음성 결과의 해석 정정

Calif 원문의 전달 기법:

1. **post_max_size vs 실제 소비 바이트 불일치**: `Content-Length` 선언만 검사하고 실제 소비량은 제한하지 않음 → chunked HTTP/1.1·lengthless HTTP/2, 입력 압축 해제 필터로 우회.
2. **`filename=""` 빈 업로드 + 중첩 필드명**: 파일 데이터가 없어 `max_file_uploads`에 계산되지 않지만 `$_FILES` 6개 항목(name, full_path, type, tmp_name, error, size)이 생성되고, `files[a][b][c]…` 중첩 시 각 항목마다 HashTable/Bucket/키 문자열이 할당된다. **본문 8MiB 미만으로 128MiB 힙을 소진**할 수 있다.

→ 우리 P14/P12는 “파라미터 수” 방식만 시험했고, **전달 형태가 달라** 음성 결과를 일반화할 수 없다. 이 정정을 §6.2·§4.9a에 반영한다.

### 7.3 커버리지 표 (자체 검증 기준)

| 항목 | 자체 결과 | Calif | 비고 |
|---|---|---|---|
| 초기 포인터 UAF 주장 반박 | **확인**(`Z_TRY_ADDREF`) | 동일 결론 | 일치 |
| `BG(serialize)` pre-RINIT 잔류 | **재현**(CLI 5/5, Apache 3/3) | Session 경로의 일부 | 일치 |
| `BG(unserialize)` pre-RINIT 잔류 | **재현**(CLI) | — | 자체 추가 |
| `BG(unserialize)` post-RINIT (FPM) | **미검증** | RCE까지 검증 | 최대 공백 |
| `PS(id)`/`PS(http_session_vars)` | **미검증** | RCE(mod_php) | 공백 |
| HashTable 부분 Bucket (109618) | **미재현** | RCE(mod_php) | 공백 |
| 공식 패치 전후 회귀 | **완료**(8.4.27/8.5.12) | 발견·신고 주체 | 자체 강점 |
| WAF 파싱 불일치 | **실측**(6/10, 우회 2) | 범위 밖 | 자체 강점 |
| multipart END | 부품 수 제한 시 **실행** 확인 | **fatal 중단 시 미도달** | 모순 아님(오류 종류 차이) |

> 2026-10-22 §8 실험으로 위 표의 미재현·미검증 3건(HashTable 부분 Bucket, `PS(id)`/`PS(http_session_vars)`, `BG(unserialize)` post-RINIT FPM)이 모두 자체 재현으로 닫혔다(§8.5).

### 7.4 보고서 문구 정정

- **“FPM에서는 요청 간 잔류가 성립하지 않는다”** → **“이번에 시험한 요청 초기화 실패 시퀀스에서는”**을 반드시 붙인다. RINIT 이후 fatal 경로(FPM)는 별개다.
- **P12(HTTP-only OOM 음성)** → “이 입력 형태에서는”으로 한정. Calif의 빈 업로드/청크/압축 기법은 미시험.
- **multipart END** → 부품 수 제한(경고 후 goto)과 fatal 중단은 다른 경로. 둘 다 참일 수 있다.

### 7.5 재검토 보강 (2026-10-22, 계획 §9.14-5로 반영)

P15~P18 실험 설계에 대해 Calif 원문·공식 advisory 문구·8.4.4 원본 소스를 대조해 재검토했고, 그 보강을 계획 §9.14에 반영했다.

1. **Path A 전제의 소스 확인(8.4.4):** `Zend/zend_hash.c:955-956`(`idx = ht->nNumUsed++; ht->nNumOfElements++;`)이 `:958`(`p->key = key = zend_string_init(...)`)보다 먼저 실행됨을 원본에서 직접 확인했다(count-before-key-allocation). 단 `:952`의 `ZEND_HASH_IF_FULL_DO_RESIZE`(realloc) 실패는 **다른 지점**이며 이 경로는 bucket을 남기지 않는다. 따라서 P15는 fatal이 key 할당(`:958`)에 착지했는지 백트레이스로 확인해야 P14(일반 파싱 OOM 관측)와 차별화된 "109618 고유 경로" 증거가 된다.
2. **P15 판정 기준 이중화:** ASAN 보고 단일 기준을 폐지했다. stale bucket이 우연히 유효·미포이즌 메모리를 가리키면 ASAN이 침묵할 수 있으므로, GDB로 `zend_hash_destroy`/`zend_array_destroy`가 `nNumUsed`까지 순회하며 미초기화 bucket(key/val)을 소비하는 관찰을 대체 신호로 병행한다. ASAN 무보고는 "이 조건에서 미재현"으로만 기록한다.
3. **Path C SAPI 정정:** 원문은 Path C가 FPM·mod_php **모두**에서 성립(앱 의존)한다고 서술한다. §7.1 표를 정정했다. P17이 FPM을 겨냥하는 것은 FPM이 자체 커버리지 공백이기 때문으로 유지한다.
4. **P16/P17에 8.4.27 대조 추가:** 기존 P15에만 있던 수정 빌드 비교를 3실험 공통으로 확장했다(Phase 4 판정 방법론과 정합). 예상 소멸 형태 — P15/P16은 전달 차단형(fatal 자체 미발생, P14의 8.4.27 결과 방식) 가능, P17은 생산자(앱 OOM fatal) 잔존 + `php_basic_early_rinit()` 재설정으로 재사용 소멸형. 두 형태를 구분해 기록하면 `root_cause_confirmed` 근거가 명확해진다.
5. **P16 비용 평가:** 생산자(요청 A)는 §4.6 Apache Bug S 재현과 동일 요청 형상이어서 소비자(요청 B — 파일 파트 없는 progress + 폼 필드 `PHPSESSID`)만 신규 구현하면 된다. GDB 체크리스트에 `PG(modules_activated)=0` 게이트·Session RSHUTDOWN 스킵·요청 B의 댕글링 PS 소비 지점을 추가. 우선 실행 후보.
6. **P18 배포 가능 조합:** mod_php는 prefork 강제·HTTP/2는 event/worker 필요 → "lengthless HTTP/2 + mod_php"는 실배포 불가 조합. FPM은 앞단(nginx/Apache)이 dechunk 후 `CONTENT_LENGTH`를 합성하는 구성이 많아 chunked 불일치는 프록시 구성 의존. 각 arm에 "실배포 성립 여부"를 기록한다. 압축 해제 mismatch는 Apache 입력 필터로 랩 재현 가능. 빈 업로드 증폭 arm은 P15 전제 기법이므로 P15와 통합 실행.
7. **P17 명시화:** 소비자는 파싱 중 decode 경로(`gdb-unserialize.py` 소비자와 동일 형상), 타이밍 제약 "A/B 사이 타 요청 금지"(§4.5) 적용, `pm.max_children=1`·순차 요청, 요청 A는 런타임 fatal이므로 정상 shutdown 후 워커 생존(500 + PID 동일)이 기대값.

## 8. P15~P18 — Calif 3경로 재현·소멸 실험 (2026-10-22, 계획 §9.14-5)

실행 환경: 기존 랩에 Apache mod_php **8.4.27**(ASAN) 빌드를 추가했다(`build-apache.sh 8.4.27`, 원본 소스 00d8bae8, prefix `install/8.4.27-apache`). 하네스: `linux/poc-patha.py`·`poc-pathb.py`·`poc-pathc.py`, `linux/gdb-patha.py`·`gdb-pathb.py`, `linux/apache-patha-sweep.sh`·`apache-patha-matrix.sh`·`apache-pathb-matrix.sh`, `linux/oom-delivery-matrix.sh`·`oom-delivery-fpm.py`. 전 실험 **메모리 오류 관측까지**(RCE 체인 비목표).

### 8.1 P16 — 109619 Path B(PS 전역 상태): **재현 3/3**, 8.4.27 소멸

생산자(요청 A)는 §4.6 Bug S 재현과 동일 요청 형상을 그대로 썼고 소비자(요청 B)만 신규 구현했다 — 파일 파트 없는 multipart(`PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS` 필드만)는 FILE_START 세션 재초기화 없이 MULTIPART_EVENT_END에 도달하고, cleanup(8.4.4 session.c:3361→3197)이 `php_session_initialize()`를 호출해 잔류 `PS(id)`·`PS(mod_data)`를 소비한다.

**8.4.4 (3/3):** 요청 A 500 + 워커 생존 → 요청 B에서 ASAN `heap-use-after-free`. 3종 스택:

| 구분 | 스택 |
|---|---|
| 할당 | `ps_open_files`(mod_files.c:412, ecalloc 40B) ← `php_session_initialize`(session.c:420) ← `php_session_rfc1867_update`(3182) ← 콜백 FILE_DATA(3321) ← `rfc1867_post_handler` ← `php_request_startup`(main.c:1871) **[요청 A 파싱 중]** |
| 해제 | `php_request_shutdown`(main.c:1979) ← `php_apache_request_dtor`(sapi_apache2.c:558) → `tracked_free_all` **[요청 A 종료 — RSHUTDOWN 없이]** |
| 사용 | `ps_files_close`(mod_files.c:141, READ 4B) ← `ps_close_files` ← `ps_open_files` ← `php_session_initialize`(420) ← `php_session_rfc1867_cleanup`(3197) ← 콜백 END(3361) ← rfc1867 ← `php_request_startup`(main.c:1871) **[요청 B 파싱 중]** |

**GDB 체크리스트(§9.14-5b) 충족**(`probe-gdb-pathb-*`): ① 요청 A `php_request_shutdown` 진입 시 `modules_activated=0`(워밍업 요청은 전부 1) ② 생산자 구간 `php_rshutdown_session_globals` 스킵 — 모듈 디액티베이션 경유 호출은 자기 요청의 shutdown 마크 이후에 찍히므로 "생산자 shutdown 마크 → 소비자 cleanup" 구간 스캔으로 판정 ③ 요청 B cleanup이 요청 A와 **동일 `PS(id)` 포인터(0x504000034a50)·동일 sid 문자열**(`pgbig…`)을 출력한 뒤 SIGABRT.

**8.4.27 (0/3, ASAN 0):** 요청 A의 fatal·`modules_activated=0`·RSHUTDOWN 스킵은 그대로지만, 요청 B cleanup이 `PS(id)=(nil)`·`PS(mod_data)=(nil)`로 시작한다. 소멸 메커니즘 = **MULTIPART_EVENT_START에서 `php_rinit_session_globals()` 선행 리셋**(8.4.27 session.c:3276-3281, 패치 주석 *"This runs before RINIT, so we need to clear these early"*) — 전달 차단이 아니라 **소비 지점 상태 리셋형** 방어. 기저 대조: 파일 파트 없는 multipart의 400은 양 버전 신규 프로세스에서도 동일(producer 무관).

### 8.2 P15 — 109618 Path A(부분 초기화 HashTable): **재현 3/3**, 8.4.27 소멸

**전제의 소스 확인(8.4.4):** `filename=""` 빈 업로드는 temp-file 경로를 건너뛰어 `upload_cnt--`(rfc1867.c:1007)가 스킵되므로 `max_file_uploads`를 소비하지 않는다(rfc1867.c:987). 부품당 6개 `$_FILES` 항목이 중첩 키로 등록된다(rfc1867.c:1146-1212 → `register_http_post_files_variable_ex` → `php_register_variable_ex` php_variables.c:270/271).

**스윕 방법론:** memory_limit × 부품 수 × 중첩 깊이 그리드에서 fatal의 할당 사이트를 PHP fatal 로그(`tried to allocate N`)와 GDB 백트레이스로 분류했다. 착지 확률은 **할당 크기에 비례**함이 관측됐다 — nest=60의 수준당 순환(`_zend_new_array` 56B → `real_init` 320B → key 32B)에서 320B real_init가 약 78%를 독점해 25회 스티어(±4,096B 위상 진동 포함) 전부 미적중. 세그먼트명을 302자로 패딩해 키 할당(≈328B)의 비중을 끌어올린 뒤 착지에 성공했다(§7.5-2의 "OOM 지점 조준" 예측을 실증).

**8.4.4 (32M, 부품 1000, nest 8, seg-pad 300): 3/3 재현.** fatal(`tried to allocate 328` = 302자 키 zend_string) 직후 teardown SEGV — `zend_array_destroy`(zend_hash.c:1839) → `i_zval_ptr_dtor` → `zend_gc_delref`(zend_types.h:1346)가 미초기화 bucket의 `p->val`(garbage refcounted 포인터)를 dtor, 프로세스 사망·응답 미송신(연결 리셋).

**GDB fatal 사이트 확정**(`probe-gdb-patha-20261022T141830`): `zend_string_alloc`(zend_string.h:176) ← `zend_string_init`(198) ← **`_zend_hash_str_add_or_update_i`(zend_hash.c:958)** ← `zend_hash_str_update_ind`(1042) ← `zend_symtable_str_update_ind`(zend_hash.h:599) ← `php_register_variable_ex`(php_variables.c:271) ← `register_http_post_files_variable_ex`(rfc1867.c:159) ← `rfc1867_post_handler`(1212) — CVE가 지목한 **key 할당이며 `nNumUsed++`(955-956) 이후 창**이다. 같은 인라인 경로의 다른 착지들(`real_init` :910/:177, `_zend_new_array` :291)은 카운터 이전이라 malformation을 만들지 않는 대조군 역할을 했다.

**미분 대조:** 28M(착지 = `_zend_new_array` 56B, `nNumUsed++` 이전)은 fatal은 발생하지만 크래시 없음·워커 생존 — 착지가 count-이후 창(955-958)일 때만 malformation이 생긴다는 인과를 입증한다.

**증폭 측정(P18 연계):** 본문 2.56MB → 32MB+ 파서 소비(≥12.5×), 초기 그리드(421KB 본문, 64M 한도)에서는 159× — Calif의 "본문 8MiB 미만으로 128MiB 소진"과 같은 계열의 증폭이 기본 INI(부품 상한 1020 = max_input_vars+max_file_uploads) 안에서 성립.

**8.4.27:** 동일 구성 400·fatal 없음·ASAN 0 — `ZEND_HAS_OOM()` 조기 종료(8.4.27 rfc1867.c:443/813/827)·`memory_hard_limit_percent` 계열의 **전달 차단형** 소멸(P14의 FPM 결과와 동일 양상).

### 8.3 P17 — 109619 Path C(post-RINIT, FPM): **재현 3/3**, 8.4.27 소멸

랩 전용 `/unserialize` 엔드포인트(web/index.php)가 `php://input`을 **애플리케이션 코드 실행 중(post-RINIT)에** unserialize한다 — 생산자가 일반 앱 패턴(session_start/maybe_unserialize 계열)을 대행. memory_limit=16M, 본문 14MB 직렬화 문자열(입력 적재는 통과, decode 문자열 할당에서 한도 초과).

**8.4.4 FPM(단일 워커, ASAN+tracked): 3/3.** 요청 A = 500 + OOM + **워커 생존**(런타임 fatal은 정상 shutdown 후 워커 재사용 — Path C의 전제). 요청 B(같은 워커, multipart+progress, 사이 요청 없음) = 502 + ASAN `heap-use-after-free` `tmp_var`(var_unserializer.re:166). 3종 스택:

| 구분 | 스택 |
|---|---|
| 할당 | `php_var_unserialize_init`(var_unserializer.re:64) ← `zif_unserialize`(var.c:1519) ← `zend_execute_script` **[요청 A 앱 실행 중]** |
| 해제 | `php_request_shutdown`(main.c:1979) ← fpm_main.c:1966 → `tracked_free_all` **[요청 A 종료, 워커 생존]** |
| 사용 | `tmp_var`(var_unserializer.re:166) ← `ps_srlzr_decode_php`(session.c:1120) ← `php_session_initialize`(488) ← `php_session_rfc1867_update`(3182) ← rfc1867 ← `php_request_startup`(main.c:1871) **[요청 B 파싱 중, pre-RINIT]** |

**8.4.27 (0/3):** 요청 A fatal+워커 생존은 동일, 요청 B는 200(ASAN 0) — `php_basic_early_rinit()`(8.4.27 main.c:1869)의 요청 시작 BG 리셋으로 재사용 소멸. **생산자 잔존 + 소비 차단형**. §7.3의 "최대 공백"(post-RINIT 생산자·FPM)이 닫혔고, 109619는 세 경로(pre-RINIT §2.7/§4.8, Path B §8.1, Path C §8.3) 모두에서 재현되었다.

### 8.4 P18 — OOM 전달 매트릭스(배포 가능 조합 포함)

본문 5.77MB(패딩 필드 4MB + 파일 1.5MB, post_max_size 4M 고정)로 각 전달 형태를 시험했다(`oom-delivery-matrix.sh`, `oom-delivery-fpm.py`):

| arm | 구성 | 결과 | 실배포 성립 |
|---|---|---|---|
| 대조(CL 선언) | mod_php, `Content-Length` 5.77MB | 400 + "POST Content-Length … exceeds the limit" 경고, 파싱 안 함 | — (선검사 정상 동작) |
| **chunked** | mod_php, `Transfer-Encoding: chunked`(무 CL) | **500, 경고 없음, memory_limit fatal(4MB 버퍼 할당) — 실제 바이트 전체가 파서에 도달** | **성립**(Apache+mod_php+HTTP/1.1) |
| gzip 입력 필터 | mod_php + `SetInputFilter DEFLATE` + `Content-Encoding: gzip`(압축본 ~20KB) | 400, PHP 로그 없음 — 이 랩 구성에서는 해제본이 PHP에 도달하지 않음 | 조건부(비기본 설정; 미성립으로 기록) |
| chunked → FPM(버퍼링 on) | nginx(`client_max_body_size 4m`) | **413** — 프록시가 실제 바이트 수로 캡, PHP 미도달 | 중화(프록시 바디 캡) |
| chunked → FPM(버퍼링 off) | nginx 스트리밍 | 400, 경고·fatal 없음 — 이 랩 구성에서는 OOM 도달 안 함 | 미확정(프록시 구성 의존) |
| 빈 업로드 증폭 | P15와 통합 실행(§8.2) | 본문 2.56MB → 32MB+ 소비 | 성립(기본 INI) |
| lengthless HTTP/2 + mod_php | — | 실험 미실시 | **불가 조합**(mod_php=prefork 강제 ↔ HTTP/2=event/worker 필요) |

해석: post_max_size 선검사는 **선언된 CL에만** 동작하므로, 선검사를 우회하는 전달 형태는 실재한다(mod_php+chunked 실증). 단 실제 배포에서는 앞단의 바디 캡(nginx 413 실증)이 같은 우회를 중화할 수 있어 — **SAPI·프록시 구성이 함께 결정하는 성질**이다(§7.5-6 예측과 일치).

### 8.5 판정 갱신과 한계

- **커버리지:** §7.3 표의 공백 3건(HashTable 부분 Bucket, PS 상태, post-RINIT FPM)이 모두 재현으로 닫혔다. 패치 효과는 세 실험 모두 8.4.27에서 소멸 — 형태는 각각 ① P16: MULTIPART_EVENT_START 상태 리셋(소비 지점), ② P17: `php_basic_early_rinit` BG 리셋(소비 지점), ③ P15: OOM 전달 차단(`ZEND_HAS_OOM` 조기 종료).
- **`root_cause_confirmed`(CVE-2026-109618) 성립** — 지정 사이트(zend_hash.c:958) 재현 + 공식 Diff 영역(php_variables/rfc1867/zend_alloc) 변경 + 수정 빌드에서 소멸이 일치(랩 조건 한정, 수동 확인).
- 한계(과장 금지): (1) P15의 착지는 memory_limit 조준이 필요한 **실험 조건**이며 임의 원격 조건의 재현률 주장이 아니다. (2) gzip arm의 미성립은 본 랩 구성의 결과이며 다른 입력 필터 구성은 미시험. (3) 세 실험 모두 위조 세션 파일/랩 엔드포인트 등 로컬 전제를 포함한다. (4) RCE 체인은 계속 비목표다.

## 9. Phase 5 — 신규 경로 탐색 (2026-10-23, 계획 §11)

두 기준(① 유계 잔존 위험 확인, ② 미지 부류 탐색 자동화)으로 수행했다. 도구: `linux/patch-protect-map.sh`, `linux/state-sites.sh`, `linux/ordering-sites.sh`, `linux/phase5-b1.sh`, `linux/phase5-b2b.sh`, `linux/fuzz-phase5.sh`, `linux/gdb-state-diff.py`. 안전 경계(관측까지만) 유지.

### 9.1 A1 — 패치 보호 목록 역추출

8.4.4→8.4.27 Diff에서 보호 관련 **57개 헝크**를 추출·분류했다(증적 `patch-protect-map/hunks.txt`). 보호 모델은 4계층:

| 계층 | 내용 | 대표 지점 |
|---|---|---|
| 할당기 이중 한도 | soft limit(=memory_limit, 초과 시 `ZEND_HAS_OOM()` 플래그만) + hard limit(기본 200%/+1G, 여기서 bailout) + `zend_mm_delayed_error` 지연 처리 + `ZEND_MM_MAX_ALLOCS`(n번째 할당 강제 실패 — 업스트림 자체 시험용) | zend_alloc.c 7헝크, main.c INI `memory_hard_limit_percent` |
| 호출부 가드 | **rfc1867.c 20곳**, php_variables.c 6곳의 `ZEND_HAS_OOM()` 조기 종료 + 등록 함수 bool화 + `safe_ferealloc(..., fallible)`(NULL 반환) | rfc1867.c:810/824/1075/1091/1218 등 |
| 구조 축소 | `array_init_singleton()`(8버킷 해시 → 최소 할당) — 증폭 표면 자체 축소 | php_variables.c 4곳 |
| 상태 조기 리셋 | `php_basic_early_rinit()`(BG serialize/unserialize·lock + `php_url_scanner_early_rinit()`), MULTIPART_EVENT_START의 `php_rinit_session_globals()`, `PS(in_rfc1867_update)` + `set_incomplete_classes_only()`(파싱 중 디코드는 미완성 클래스만, 사용자 코드 개입 차단) | main.c:1869, session.c:3280, var_unserializer.re |

**핵심 관찰(A3 연계): `Zend/zend_hash.c` 자체에는 가드가 0개다.** count-before-key-allocation 구조(`:955-958`)는 8.4.27에도 그대로 있으며, 방어는 전적으로 호출부 사전 점검과 soft/hard 이중 한도에 의존한다.

### 9.2 A2/A3 — 후보 열거와 S9 체크리스트

- **A2(동형 stale-state)**: 잔류 부류는 "소비가 pre-RINIT인 상태"로 유계다(그 외는 모듈 RINIT이 리셋). pre-RINIT 도달 전역을 `php_hash_environment` 트리로 열거: 심볼 테이블, `SG(rfc1867_uploaded_files)`, PS 전역, BG(serialize/unserialize), url_scanner 상태(sid 등록: session.c:1604). **INIT/DESTROY 쌍 조사**: gmp·sysvshm·phar·spl·sysvmsg의 (un)serialize는 모두 공유 BG 컨텍스트를 쓰며(`php_var_(un)serialize_init`의 BG 캐시) 별도 상태가 아니다 — 생산자 다양성일 뿐 부류는 동일.
- **S9 체크리스트 실행**(Calif php-unserialize-audit): ① `Serializable::unserialize` 재진입 — 실재(var_unserializer.re:776, decode 중 사용자 코드)하나 8.4.27에서 호출 후 `ZEND_HAS_OOM()` 점검 추가·rfc1867 컨텍스트는 `incomplete_classes_only`로 차단. ② `__wakeup`/dtor 지연 — `var_push_dtor` 목록은 var_hash 컨텍스트 수명에 귀속(기존 부류). ③ `var_hash` 수명 — 공유 BG 캐시(기존 부류). ④ 세션 디코더 차이 — **핸들러 간 보호 차이 없음**: `php_session_decode`가 전 핸들러를 동일 `zend_try`로 감쌈. → 신규 미보호 경로 없음(정적).
- **A3(count-before-init)**: 99쌍 스캔(증적 `ordering-sites/pattern-hits.txt`). 유효 후보는 ① `rfc1867.c:1123`(lbuf 성장 — 8.4.27에서 fallible 전환 + NULL 점검) ② `SG(rfc1867_uploaded_files)` 삽입(:1105, 같은 zend_hash 부류 — 8.4.27은 FILE_END 가드가 등록 전 취소) ②' 심볼 테이블 삽입(P15 부류). 나머지 97쌍은 MINIT·컴파일 시점 또는 길이 대입 등 무해.

### 9.3 Stage B — 후보 5개 동적 판정

| # | 후보 | 구성 | 8.4.4 | 8.4.27 | 판정 |
|---|---|---|---|---|---|
| B1-1 | url_scanner 상태(trans_sid) | `use_trans_sid=1` + Path B 시퀀스 | 재현 3/3 — 단 스택은 기존 PS 경로와 동일(`php_session_initialize`/`ps_files_close`), url_scanner 단독 소비는 이 시퀀스에서 미관측 | 소멸 0/3 | `already_patched`(early reset) + 동일 부류 |
| B1-2 | `php_serialize` 핸들러 | 핸들러별 위조 세션 형식 | 재현 3/3, 동일 스택 | 소멸 0/2 | `already_patched`(핸들러 무관 — S9④와 일치) |
| B1-3 | `php_binary` 핸들러 | 〃 | 재현 3/3, 동일 스택 | (부류 동일로 생략) | `already_patched` |
| B2-1 | `uploaded_files` 부분 초기화 | 실제 파일 파트(**`max_file_uploads=1000` 필요 — 실제 파일은 카운터를 소모함을 재확인**, 기본 20에선 도달 불가) | OOM 도달(2M~2.8M, tried=320/56/34B — 착지 분산), teardown 크래시는 이 조건들에서 미관측 | 정적으로 FILE_END 가드가 등록 전 취소 | `이 조건에서 미재현`(부류는 보호됨) |
| B2-2 | hard limit 잔여 창 | chunked 18.9MB 본문 > soft 8M·hard 16M | fatal(500) 재현, 메모리 오류 없음 | **fatal(500) 재현** — hard bailout은 여전히 발생, 메모리 오류 없음 | 창 이론상 존재하나 **현실적 입력 상한에서 관측 못함**(아래 사유) |

**B2-2 구조적 사유:** soft limit 초과 후에는 호출부 가드가 소규모 할당 성장을 차단하고(fatal까지의 8MB 여유분 동안 `ZEND_HAS_OOM()`=true), hard limit으로 한 번에 점프하는 단일 대형 할당은 값/파일명 문자열처럼 카운터 이전의 무해한 대상에만 발생하며, 입력 상한(부품 1020, 변수 1000) 안에서는 다중 MB 규모의 구조 성장이 불가능하다. 즉 8.4.27의 방어는 "fatal 방지"가 아니라 "fatal이 부분 초기화 구조에 착지할 가능성 제거"로 작동한다.

### 9.4 C1/C2 — 탐색 자동화

- **C1 퍼저**: 코퍼스 통합(공식 19 + 자체 9 = 28시드: 세션 핸들러 3종 형식·progress 구조·`R:`/`r:` 참조·`C:` Serializable·`__PHP_Incomplete_Class`·32단계 네스팅·64KB 문자열). 사전(dict) 생성 이슈는 최소 빌드에서 지속(빈 출력) → 코퍼스 강화 모드로 운용. 3회 장기 실행 결과는 아래 표.
- **C2 `gdb-state-diff.py`**: 요청 경계마다 BG(serialize/unserialize)·PS(id/mod_data)·url_adapt 호스트 표·`modules_activated`를 덤프해 잔류를 가설 없이 diff. 8.4.4에서 **두 부류의 잔류를 자동 포착** — 파싱 중 생산자 후 `ser_level=1`+`ps_id`/`ps_mod` 댕글링 운반, 런타임 생산자 후 `unser_level=1`+`unser_data` 댕글링 운반. 8.4.27에서는 **모든 전이에서 잔류 0**(같은 fatal 발생 하에) — 패치 소멸의 자동 확인.

| C1 실행 | 시간 | 실행 횟수 | crash artifact | 코퍼스 단위(누적) |
|---|---|---|---|---|
| run 1 | 25분 | 8,431,226 (5,617 exec/s) | **0** | 1,441 |
| run 2 | 25분 | 7,672,622 (5,111 exec/s) | **0** | (증감 병합) |
| run 3 | 25분 | 7,513,880 (5,005 exec/s) | **0** | 1,323 |

총 약 **2,362만 회** 실행, 크래시 0 — 커버리지 cov:2,399/ft:8,510 수준에서 신규 단위는 계속 발견되나(누적 코퍼스 ~1.2MB) 메모리 오류 미발생. 음성은 "이 구성·시간에서 못 찾음"이다(야간 8h급은 미수행, `fuzz-phase5.sh`로 지속 가능).

### 9.5 커버리지 보고 (봤음 / 못 봄)

- **봤음**: 8.4.4↔8.4.27 전체 보안 Diff(57헝크), pre-RINIT 도달 전역, 전 확장 (un)serialize INIT/DESTROY 쌍, count-before-init 99쌍, 후보 5종 동적, 상태 잔류 자동 diff(양 버전), unserialize 퍼징(3회).
- **못 봄(한계)**: 8.3/8.2 라인과 master 스캔(정적 스코프로도 미수행 — A4에서 8.4/8.5로 확정), 상용 WAF/CRS, multipart 직접 퍼저 타깃(신규 개발 = 비목표 유지), 야간 8h급 장기 퍼징(세션 내 25분×3으로 대체 — 아래 커밋 후 지속 실행 가능), 기타 확장(phar/spl 등)의 개별 동적 시험.

### 9.6 종합 판정

- **신규 경로(미보고 취약점): 발견 없음** — 판정 어휘 `not_found(못 찾음)`로 기록한다. 완전성은 원리적으로 불가하며 본 탐색의 음성은 "이 스코프에서 못 찾음"이다.
- **기준 1(유계 잔존 확인): 충족** — 후보 열거 완료 + 상위 5종 동적 판정 완료. 모든 후보가 기존 2부류(stale-state·count-before-init)로 수렴하고 패치 범위 내다. 유일한 구조적 발견은 §9.3 B2-2(hard bailout은 존재하나 착지 무해성의 구조적 사유).
- **기준 2(탐색 자동화): 충족** — C2 잔류 diff 도구 신설(양 부류 자동 포착·소멸 확인), C1 코퍼스 통합 퍼징 3회 가동.
- 발견물 없음으로 D1(신고 절차)은 미발동. 재현 스크립트·증적은 `patch-protect-map/`, `state-sites/`, `ordering-sites/`, `poc-patha-*realtfiles`, `b2b-hardlimit-*`, `gdb-state-diff-*`, `fuzz-phase5-*`.

## 10. Phase 5 v1.1·v2 — 이슈 #1 신뢰성 보강과 탐색 고도화 (2026-10-23, 계획 §12)

### 10.1 v1.1 — 이슈 #1 반영 (증적 검증·판정·러너 신뢰성)

| 항목 | 구현 | 검증 |
|---|---|---|
| P0 매니페스트 검증기 | `check_manifest()`가 `hash  file`/`hash *file` 양 형식 수용, 미해석 행·0건 검사를 **실패**로 판정, 항목/성공/누락/불일치 통계 출력. `--self-test`로 6개 픽스처(정상 2·오류행·0건·불일치·누락) 추가 | self-test **6/6**, 실제 트리 7,990/7,990 검증 통과 ~~(현행 매니페스트에 `*` 행 0건 — 실제 무결성 훼손은 없었음을 재확인)~~ **[정정, 계획 §12.6 R7] 10/22·10/23 매니페스트는 전 행이 `*` 형식 — 수정 전 검증기는 0행을 검사하고 통과했다. 10/22 매니페스트 소급 검증: 4,351 OK / 19 불일치(고정 이름 Apache 런 디렉터리 로그가 10/23 재실행으로 덮어써짐, R7a). 검사 수치(7,990 vs 커밋 메시지 10,458)는 v1.2에서 정리** |
| P1 P15 판정 강화 | ① `poc-patha.py`: `fatal_and_teardown_memory_error`가 **teardown 소비 프레임**(zend_array_destroy 등 7종) 결합 시에만 채택, 단순 ASAN은 `fatal_and_other_asan`으로 분리, 56B 착지는 `pre_counter_crossing_hint`로 자동 표시 ② `gdb-patha.py`: OOM 시점에 `_zend_hash_str_add_or_update_i` 프레임의 `nNumUsed`·마지막 bucket을 덤프 | 재검: 크래시 구성 teardown 프레임 4종 결합, 대조(28M)는 `fatal_only`+`pre_counter_crossing_hint=true`. GDB 관측 — **`nNumUsed=1`·`nNumOfElements=1` 상태에서 bucket[0].key=`0xbebebebebebebebe`(ASAN 미초기화 패턴), val_type=190** → "카운트 후 미초기화 bucket"이 한 번의 실행으로 증명 |
| P1 퍼저 정비 | 시드 3곳 형식 수정(정상 시드 실제 통과), 세션 전용 형식은 별도 분류, 비정상 시드 3종 분리, 정상 시드 `unserialize()` **positive control**, 실행 상태(rc·timeout·crash·units) `runs.json` 분리 기록, 커버리지 한계 주석 | positive control **8/8**(초기 실행 8/9 → `big|s:...`가 단독 unserialize 입력이 아님을 컨트롤이 스스로 포착 → 분류 수정). 2분 스모크 108만 회·크래시 0 |
| P1/P2 러너 신뢰성 | 매트릭스 `|| true` 제거·`summary.json`(항목 보존)·기대(재현/소멸) 불충족 시 non-zero 종료. `poc-pathb` OOM 판정을 요청 A 이후 로그 구간으로 한정. `poc-pathc` 생산자 fatal을 엔드포인트 귀속(`index.php`)으로 판정 + A/B 동일 실행 귀속. `gdb-state-diff` 스코프 명시(등록 상태 고정 분포) | patha 매트릭스 8.4.4 3/3 ok·대조 ok(종료 0), pathb 8.4.4 ok·8.4.27 ok(extinct). 중간 발견: 초기 `rc != 0` 문자열 비교 오류는 픽스처 재실행으로 적발·수정 |
| 문서 기준점 | docs/README(§9·§11·§12·최신 매니페스트·`--self-test` 안내), exec summary v3(2026-10-23 기준) | — |

### 10.2 v2 Stage 0 — ground-truth 회귀 세트 (`linux/ground-truth.sh`)

3경로를 **도달(reached) / 오류 발생(error_triggered) / 메모리 오류 관측(memory_error) / 기대 충족(expectation_met)**으로 분리해 버전별 기대(취약=재현, 수정=소멸)와 대조.

| 버전 | P15 | P16 | P17 | 판정 |
|---|---|---|---|---|
| 8.4.4 | 도달·fatal·teardown 메모리 오류 ✓ | 도달·fatal·UAF ✓ | 도달·fatal(unserialize 귀속)·UAF ✓ | **ok=true, exit 0** |
| 8.4.27 | 메모리 오류 없음 ✓ | 메모리 오류 없음 ✓ | 메모리 오류 없음 ✓ | **ok=true, exit 0** |

지표 정의(`reached/error_triggered/memory_error` + v2 탐색 지표 `error_site_coverage/request_transition_coverage/invariant_violations/time_to_first_valid_finding`)를 매 실행 결과에 함께 기록. 이슈 #2 MVP 기준(기존 경로 분별 + 오탐 없음) 충족.

### 10.3 v2 Stage 1 MVP — 요청 수명주기 시퀀스 러너 (`linux/lifecycle-fuzz.py`)

시퀀스 문법: 생산자{파싱 OOM, 런타임 unserialize OOM} × 중간 요청{없음, 정상 요청(음성 대조)} × 소비자{multipart 업로드, 파일 파트 없음} = 8 전이 × 2 반복(8.4.4, CLI 서버).

- **16/16 기대 충족 — 오탐 0, 위음성 0, 전이 커버리지 8/8.**
- 모델이 세 소비 지점을 자동 구분: 파싱 생산자+업로드 → `php_add_var_hash`(BG(serialize)), 파싱 생산자+파일 없음 → `ps_files_close`(PS 잔류, Path B), 런타임 생산자+업로드 → `tmp_var`(BG(unserialize), Path C).
- 음성 대조: 생산자-소비자 사이 정상 요청 1개만으로 전 시퀀스 잔류 소거 관측. 런타임 생산자+파일 없음 소비자는 `PS(id)`가 NULL이라 새 빈 세션을 만들어 decode가 생략됨 → 메모리 오류 없음(모델에 반영한 소비 조건).
- 한계: CLI 프로파일만(MVP) — mod_php/FPM 프로파일, 상태 정규화 ID, 커버리지 피드백은 후속.

### 10.4 v2 Stage 2 MVP — 오류 지점 지도 + 할당 실패 주입 (`linux/fault-site-map.py`)

- 분류 스캔(휴리스틱): `count_before_fallible` 44, `init_fallible_destroy` 5, `global_ptr_request_free` 7, `refcount_then_fallible` 13, `reentrancy` 0(정규식 창 한계 — `.re` 생성기/콜백 흐름은 AST판 필요). 8.4.27 가드 교차표 동반. **후보 가설 목록일 뿐 판정 아님.**
- **`ZEND_MM_MAX_ALLOCS` 실증**: 8.4.27 + tracked 할당자에서 `ZEND_MM_MAX_ALLOCS=5` → 스크립트 실행 중 5번째 할당이 우아하게 실패(`zend_alloc.c:3297`, "tried to allocate 40 bytes") — 업스트림 오류 주입 훅의 사후-시작업 사용성 확인. **제약 재확인**: 훅은 `php_hash_environment()` 이후(main.c:1914) + tracked 전용 → pre-RINIT 파싱 창은 별도 계측 필요(원본 재검증 전 확정 금지, §12.1).

### 10.5 종합

- 이슈 #1의 완료 기준 4개 충족(0건 통과 불가·오진 집계 차단·시드 구분과 기록 일치·실패 전파).
- 이슈 #2의 Stage 0·1·2 MVP 충족(ground-truth 분별 + 시퀀스 러너 오탐 0 + 오류 지점 지도·주입 실증). Stage 1 SAPI 확장·상태 정규화, Stage 2 AST판, Stage 3·4는 잔여.
- 신규 경로 발견: 없음(`not_found`, 스코프 한정 유지).

### 10.6 v1.2 — 이슈 #1 후속 리뷰 반영 (2026-10-23, 계획 §12.6.3, **G0**)

| 항목 | 구현 | 검증(픽스처·실측) |
|---|---|---|
| P0 ground-truth | 실행마다 `run_id`를 발급하고 하위 러너 3개에 출력 경로(`MATRIX_OUT`, `--summary-out`)와 run_id를 명시 전달(`ls -t` 제거). 종료 코드 수집, 판정은 `linux/ground-truth-eval.py`로 분리. 수정 버전 소멸 = **입력 유효성 ∧ 도달 ∧ 차단 지점 분류 ∧ 메모리 오류 없음** | `ground-truth-eval.py --self-test` **12/12**(하위 러너 rc=139·이전 실행 결과·타 버전 결과·결과 파일 부재 → exit 1, 미도달 입력·생산자 미발생·실효 memory_limit 불일치·소비자 미실행·`no_fatal` 부분문자열·대조군 착지 이상 → exit 2) |
| 구 판정 결함(추가 발견) | 기존 `ground-truth.sh`는 `'fatal' in str(verdict)`로 판정 → `no_fatal`도 매칭. 8.4.27 P15를 `reached=true, error_triggered=true`로 잘못 기록했다(실제는 fatal 없음 400) | 새 판정에서 8.4.27 P15 `error_triggered=false`, `block_point=delivery_blocked` |
| P1 퍼저 | `run_failed()`로 결합을 명시(`{crash>0} \|\| {rc∉{0,124}}`), positive control 실패 시 퍼징 전 exit 3 | `fuzz-phase5.sh --self-test` **9/9**. 구식 `A \|\| B && C`에 crash=1·rc=124를 넣으면 실패로 잡히지 않음을 재현 |
| P1 pathb/patha 러너 | pathb: `/tmp` 고정 경로 → `$outdir/iter-$i.json`, rc∉{0,1}이면 `runner_failed`, run_id·version 불일치는 `foreign_result`. patha: 회차별 `raw-<label>/`로 원시 결과 보존. 두 러너 모두 Apache 런 디렉터리를 `apache-lab-<ver>-path{a,b}-<run_id>`로(R7a 재발 방지). `poc-patha`가 `run_id`·응답 본문·`script_reached` 기록 | `linux/tests/matrix-fixtures.sh` **3/3**(이전 실행 결과 주입 → `foreign_result` exit 1, rc=139 → `runner_failed` exit 1, 동일 구성 2회 → 원시 결과 2개·run_id 일치) |
| P1 gdb-patha | 판정 = ① fatal 사이트(nNumUsed++ 이후 key 할당) ∧ ② 카운트된 슬롯 key가 할당자 채움 패턴(반복 바이트) ∧ ③ **같은 실행**의 정지 스택이 teardown 프레임을 포함하고 같은 패턴 포인터에서 fault. 일부만 충족하면 `candidate`. GDB 스크립트가 정지 시 `bt`를 자동 기록. 런 디렉터리도 회차별 | `--self-test` **5/5**(임의 비영 포인터·teardown 부재·다른 포인터 fault → `candidate`, 28M 대조 → `not_observed`). 실측 8.4.4: 32M → `counted_uninitialized_bucket_consumed`(key=`0xbe…`, fault `zend_gc_delref(p=0xbebebebebebebebe)` ← `zend_array_destroy`), 28M → `hash_resize`/`not_observed` |
| P1 fault-site-map | 대상 파일별 present/missing·행 수, 누락 시 `scope_incomplete` exit 2(`--allow-missing`으로만 완화). 출력 디렉터리 타임스탬프화 | `--self-test` **2/2**. 실측: **11/11 파일, 20,255행** — §10.4 수치(44/5/7/13/0)의 분모 확정 |

**G0 재실행 (최종 코드, 순차 실행):**

| 버전 | run_id | P15 | P16 | P17 | 종료 |
|---|---|---|---|---|---|
| 8.4.4 | `gt-20261023T025503-8.4.4-385` | 유효·도달·fatal·teardown 메모리 오류 ✓, 대조 pre-counter ✓ | 유효·도달·fatal·UAF ✓ | 유효(실효 16M)·도달·unserialize fatal·UAF ✓ | **0** |
| 8.4.27 | `gt-20261023T025519-8.4.27-546` | 유효·도달(앱 응답 `{"ok":false}`)·**fatal 없음**·`delivery_blocked` | 유효·도달·fatal 잔존·`consumer_reset` | 유효·도달·fatal 잔존·`consumer_reset` | **0** |

→ 계획 §9.14-5d의 예상 소멸 형태(P15 전달 차단형, P16 소비 지점 리셋형, P17 생산자 잔존+소비 차단형)가 이제 **자동 판정으로** 기록된다. §12.6.2의 Stage 0 "재검증 필요"는 해소됐다.

**증적:** export 후 매니페스트를 재생성했다(`docs/evidence-manifest-20261023-v12.sha256`, 10,699행). WSL에서 `verify-evidence`를 실행한 결과 poc·gdb·manifest 모두 passed, **10,699/10,699 검사**.
- **경로 주의:** Windows Python으로 실행하면 PoC 증적의 절대 Linux 경로(`/home/phplab/...`)를 찾지 못해 실패한다. 반드시 WSL의 `python3`로 실행해야 한다.
- **소급 확인:** 20261023 매니페스트는 현 트리 대비 10,457 OK / **1 불일치**다. 불일치 파일 `evidence/fault-site-map/fault-site-map.json`은 이번 작업의 첫 `fault-site-map.py` 실행(출력 경로를 회차별로 바꾸기 전)이 덮어쓴 것으로, R7a와 같은 부류다. 이후 출력 경로를 타임스탬프화했다.
- **수치 정리:** §10.1의 "7,990"은 v1.1 작업 중간 시점의 수치로 보이며 근거 기록이 남아 있지 않다. 확정 수치는 20261023 매니페스트 10,458행과 이번 v1.2 매니페스트 10,699행이다.

### 10.7 v2 G1·G2 — 피드백 탐색 루프 (`linux/lifecycle-explore.py`, 계획 §12.6.4)

**Stage 1a — 고정 회귀 매트릭스 신뢰성 보강 (`lifecycle-fuzz.py`):**
- 생산자 착지 판정을 추가했다. 요청 A 이후 로그 구간에서 fatal 위치를 확인하며, parse_oom은 `Unknown:0`, runtime_oom은 `index.php`의 `unserialize()` 줄(31)이어야 한다. 이전 실행 로그에는 `file_get_contents` 줄(30)에 착지해 잔류를 남기지 못한 사례가 있었다.
- interpose 요청이 실패하면 `invalid_control`로 판정한다.
- ASAN 보고는 서버 pid와 일치할 때만 인정한다.
- 기대값을 버전별로 나눴다. 8.4.27에서는 소멸이 정상이다.
- 실행마다 디렉터리를 새로 쓴다. 기존 `lifecycle-<n>-<ver>` 디렉터리는 재실행 때 재사용돼 서로 다른 실행의 fatal 로그가 섞여 있었다(R9④ 실증).
- 실효 memory_limit을 로그에서 기록한다.
- 결과: 8.4.4 **8/8**, 8.4.27 **8/8**(소멸을 위음성으로 집계하지 않음). 오탐·위음성·무효 0건.
- 부수 수정: `ok` 필드가 리스트를 반환하던 오류.

**탐색기 구성 (G1~G4 공용):**
- **생성:** 액션 문법(10종, 일부 파라미터 포함) × 길이 1~6 × memory_limit 2종. 공간 크기는 약 6.4×10⁶이다. 실행 전 문법 검사를 거친다.
- **실행:** 시퀀스마다 새 ASAN CLI 서버를 띄운다(시퀀스 안에서는 프로세스 상태 유지).
  - **생존 확인은 프로세스 상태로만 한다.** HTTP 생존 탐침은 그 자체가 정상 요청이라 잔류를 지우기 때문이다. 초기 설계의 이 결함은 구현 중 발견해 수정했다.
- **관측:** 요청마다 응답 클래스, 실패 지점(로그 구간을 정규화한 `oom:2^k@file:line`), pid로 귀속한 ASAN 시그니처를 기록한다. gdb 관측기는 여기에 `php_request_startup` 시점의 정규화 상태를 더한다. 포인터는 주소 대신 null/fresh/carried로만 표기한다.
- **오라클:** `state_change_observed` → `invariant_violation_candidate`(요청 소유 상태가 다음 요청 시작에 살아 있음) → `memory_error_confirmed`.
- **응답 없음 처리:** 응답이 없는 살아 있는 프로세스는 12초 유예 후 `hung`으로 분류한다. 이때 쓰는 탐침이 잔류를 지우므로 시퀀스는 그 자리에서 종료한다.
- **선택·변이:** 새 키를 낸 시퀀스를 코퍼스에 저장한다. 가중치 `(1+new)/√(1+picked)`로 부모를 고르고 변이 8종을 적용한다. 선택 로그는 `scheduler.jsonl`에 남는다.
- **검증:** `--replay`로 재실행, 단계 단위 최소화, `--diff-version` 차등을 수행한다.
- 자체 테스트 **11/11**.

**캠페인** `ex-20261023T031119-8.4.4-on-s1` (8.4.4, 피드백 ON, gdb 관측, 900s, 양성 시드 4개):

| 게이트 | 결과 |
|---|---|
| **G1** | 실행 85건 중 생성 81건. 81건 모두 서로 다르고 문법 검사를 통과했으며(거부 0), 80건이 고정 8조합 밖이다. 길이 분포 1:8 / 2:28 / 3:25 / 4:15 / 5:4 / 6:1 → **통과** |
| **G2** | 코퍼스 22개, 최대 깊이 6, 선택 106회, 생성 항목 16개가 부모로 재선택됐다. 계보: `health`(시드) → `runtime_oom` → `+parse_oom`(새 실패 지점) → `+parse_oom`(carried 상태 최초 관측) → swap → replace(`abort_upload`) → param → 자식이 **ASAN `heap-use-after-free:tmp_var>var_tmp_var>ps_srlzr_decode_php` 발견(684.7s)** → **통과** |

- 발견된 시그니처는 알려진 P17(BG(unserialize)) 부류다. 소비자는 `upload_small`이 아니라 `parse_oom`(큰 세션 progress decode)인 변형이다.
- 고유 키: S 4 / T 26 / F 3 / A 1.

**부수 관측 — `parse_oom → parse_oom`(8M) 요청 B 멈춤:**
- 관측자 효과 대조: gdb 없이 2/2, gdb 있이 2/2 재현됐다. gdb 관측의 부작용이 아니다.
- 원인 확정:
  - 요청 A의 fatal 뒤에도 큰 세션 파일 fd(5)가 열린 채 `FLOCK WRITE`를 보유한다. PS 상태 미정리, 즉 Path B 잔류다.
  - 요청 B가 같은 파일을 fd 6으로 열어 `flock`에서 대기한다(`syscall 73`, `wchan=locks_lock_inode_wait`, CPU 0). 같은 프로세스 안의 **자기 교착**이다.
- 8.4.27에서는 같은 시퀀스가 200으로 정상 처리된다.
- 판정: 신규 메모리 오류가 아니다. **알려진 CVE-2026-109619 Path B 부류의 다른 영향(워커 교착/DoS)**이며 `already_patched`다. D1은 해당하지 않는다.
- 이후 탐색기는 `H:` 키로 멈춤을 별도 피드백으로 기록한다.

**증적:** `docs/evidence-manifest-20261023-g2.sha256`(11,336행). `verify-evidence`(WSL) 11,336/11,336 passed.
**한계:** code-edge 커버리지는 아직 피드백에 없다. 상태·실패 지점·ASAN·멈춤 키만 쓴다. 측정은 gdb 관측 기준이다.

### 10.8 v2 단계 8 — 오라클 통합·Stage 2 주입 연결 (2026-10-23, 계획 §12.6.5-8)

- **1e 오라클:** 별도 `state-oracle.py`를 두지 않고 탐색기 관측 단계에 통합했다. 판정 사다리는 `state_change_observed` → `invariant_violation_candidate` → `memory_error_confirmed`이며, `patch_difference_confirmed`는 `--diff-version`으로 판정한다. persistent 메모리와 요청 메모리는 "요청 시작 시점에 요청 소유 상태가 살아 있는가"로 구분하고, 주소 대신 null/fresh/carried로 정규화한다.
- **관측자 효과 대조:** §10.7의 멈춤을 gdb 있이 2회, 없이 2회 돌려 같은 결과를 얻었다.
- **Stage 2 연결:** `ZEND_MM_MAX_ALLOCS`를 시퀀스 단위 파라미터 `fault ∈ {0,30,120,500,2000}`로 문법에 편입했다(`--faults`).
  - 요청 단위로는 걸 수 없다. 사용자 코드의 `putenv()`는 RSHUTDOWN에서 원복된다.
  - 실패 지점 ID에는 `inj:` 접두어(주입 여부)와 debug 빌드의 할당 C 위치를 붙인다.
  - 위치가 늘 `zend_alloc.c:32xx`(할당기 내부)라 C 위치의 정보량은 낮다. 분별력은 PHP 측 위치(`index.php:N`/`Unknown:0`)에서 나온다.
- **8.4.27 주입 탐색** `ex-20261023T033844-8.4.27-on-s1`(피드백 ON, gdb, 600s):

| 항목 | 값 |
|---|---|
| 실행 | 163건(fault 0:60 / 30:35 / 120:26 / 500:24 / 2000:18) |
| 고유 실패 지점 | **12**(주입 10 + 자연 2). 예: `inj:oom:2^4@index.php:10`(스크립트 컴파일 중), `inj:oom:2^8@Unknown:0`(시작·종료 단계), `inj:oom:2^8@index.php:34`, `oom:2^22@index.php:31`(자연 unserialize OOM) |
| 오라클 | 387 단계 전부 `none`: 메모리 오류 0, 불변조건 후보 0, 멈춤 0 |
| 판정 | **`not_found`**(8.4.27, CLI 서버, 사후 시작 주입 범위 한정) |

- **한계:**
  - `inj:` 표기는 시퀀스 단위다. 주입이 걸린 시퀀스에서 생긴 자연 OOM도 `inj:`로 표기된다(예: `inj:oom:2^21@Unknown:0`).
  - pre-RINIT 파싱 창은 주입 범위 밖이다(§12.3 제약 유지).

### 10.9 v2 G3·1f·G4 — hold-out 재발견, 최소화·차등, 피드백 ON/OFF 비교 (2026-10-23)

**설정** `explore-g34-20261023T034906-8.4.4`:
- 8.4.4, CLI 서버, gdb 관측, 900s × (ON 3회 + OFF 3회, RNG seed 1~3), 순차 실행.
- 초기 코퍼스는 양성 단일 요청 시드 4개다. 정답 쌍 `parse_oom>upload_nofile`(P16), `parse_oom>upload_small`(Bug S), `runtime_oom>upload_small`(P17)은 시드에서 제외했다(`--exclude-pairs`, summary에 기록).
- 문법 공간은 **6,514,872**이고, 실행 수는 회당 약 120~140이다.

**G3 — hold-out 재발견** (`explore-report.py g3`):

| 경로(소비자 시그니처) | ON s1 | ON s2 | ON s3 | OFF s1 | OFF s2 | OFF s3 |
|---|---|---|---|---|---|---|
| P16 (`ps_files_close`) | ✗ 생성 단계 | 104s | 178s | 612s | 109s | 493s |
| Bug S (`php_add_var_hash`) | 466s | ✗ 생성 단계 | 526s | 216s | 464s | 224s |
| P17 (`tmp_var`) | 637s | 80s | 186s | 88s | 411s | 63s |

- 재발견 경로가 정답 쌍만은 아니다. 예: P17은 `runtime_oom → parse_oom`, Bug S는 `session → parse_oom → upload_cookie`로도 찾았다.
- ON의 미발견 2건은 모두 **생성 실패**다. 정답 쌍이 한 번도 생성되지 않았고, 도달·판정 단계의 실패는 없었다.
- **해석:** 공간은 열거 불가 규모지만, 정답이 길이 2의 인접 쌍이라 무작위 샘플링(OFF)도 3/3을 재발견했다. 따라서 이 문법에서의 재발견은 **피드백의 효과가 아니라 문법 밀도의 결과**로 판정한다(§12.6.4 G3 주의 조항).

**1f — 재현·최소화·차등** (`--replay`):

| 대상 | 재현 | 최소화 | 8.4.27 차등 |
|---|---|---|---|
| P17 발견(ON s1, 6단계 `abort_upload, runtime_oom, runtime_oom, abort_big, parse_oom, runtime_oom`) | 2/2 | **`runtime_oom(14MB) → parse_oom` 2단계** | 소멸 |
| Bug S 발견(ON s1, `session, parse_oom, upload_cookie`) | 2/2 | 이미 최소(어느 단계를 빼도 시그니처가 사라짐. `session`은 쿠키 소비자의 전제) | 소멸(`upload_cookie` 200) |

중복 제거는 시그니처 키(오류 종류 + 상위 3개 함수) 단위로 했다. 6회 실행의 고유 시그니처는 위 3종뿐이며, 모두 알려진 부류이고 8.4.27에서 소멸한다.

**G4 — 피드백 ON vs OFF** (동일 버전·관측기·예산·시드 집합, 3회씩):

| 지표(평균, 범위) | ON | OFF |
|---|---|---|
| 실행 수 | 122 (120–125) | 137.3 (136–138) |
| 고유 상태 전이(T) | 24.3 (23–26) | **28.0** (27–29) |
| 고유 정규화 상태(S) | 4 | 4 |
| 고유 실패 지점(F) | 3.67 (3–4) | 4 |
| 고유 ASAN 시그니처(A) | 2.33 (2–3) | **3** (3–3) |
| 시그니처당 실행 수 | 54.3 | **45.8** |
| 첫 검증 오류까지 시간 | 241s (80–466) | **87s** (63–109) |

**판정:** 이 문법·관측 체계에서 현재 피드백(정규화 상태·실패 지점·ASAN 키 + 새 키 가중 스케줄러)은 무작위 생성 대비 **유의미한 개선이 없고 모든 지표에서 열세**다.

원인 추정:
1. 상태 피드백이 4종으로 금방 포화돼 스케줄러가 초기 계보 주변에 머문다.
2. 변이가 긴 시퀀스와 멈춤(12s 유예)을 늘려 실행 수가 준다.
3. 정답 밀도가 높아 무작위 샘플이 유리하다.

§12.3 가드레일에 따라 **전략 폐기 여부는 사람의 판단 사항**이다. 보완 후보는 code-edge 피드백, 포화 키 감쇠, 길이 페널티다.

### 10.10 v2 G5 — SAPI 프로파일 비교 + FlowFusion 브리지 (2026-10-23)

**SAPI 프로파일** (`linux/explore_sapi.py`, `lifecycle-explore.py --sapi cli|apache|fpm`)

프로파일 구성:
- **apache:** prefork mod_php, `httpd -X`. 단일 프로세스라 fatal 뒤에도 같은 프로세스가 다음 요청을 처리한다.
- **fpm:** nginx + FPM `pm.max_children=1`. 워커가 교체되면 잔류가 사라지므로 시퀀스를 끝내고 `worker_lost`로 기록한다(§12.3 워커 교체 대조군).
- apache·fpm은 빠른 관측기(실패 지점·ASAN·멈춤)만 쓴다.

검증 순서:
1. 사전 확인: mod_php에서 P16(`ps_files_close`)과 FPM에서 P17(`tmp_var`)을 탐색기 실행기로 재현했다. 둘 다 8.4.27에서 소멸했다.
2. 첫 배치는 **무효 처리**했다. mod_php에서 Path B 자기 교착 요청이 SIGTERM으로 종료되지 않아 포트를 쥔 httpd가 남았고, 이후 실행이 모두 시작에 실패했다(실행 18건 중 9건이 하네스 오류).
   - 수정: SIGKILL로 승격하고 포트 해제를 확인하도록 바꿨다. 하네스 오류가 3회 연속이면 캠페인을 중단하고 exit 3으로 끝내며, 오류 수를 summary에 기록한다.
3. 수정 후 재실행: `explore-g5-20261023T054912-8.4.4`(seed 1, 600s, 동일 hold-out, 4회 모두 하네스 오류 0).

**비교** (`explore-report.py g5 --cutoff 600`. CLI는 G3/G4 seed 1 실행을 600s로 절단):

| 프로파일 | 실행 | 전이 T | 실패 지점 F | Bug S | P16 | P17 | 멈춤 | ASAN 없는 워커 소실 |
|---|---|---|---|---|---|---|---|---|
| CLI OFF | 93 | 25 | 4 | 216s | – | 88s | 1 | 0 |
| CLI ON | 89 | 20 | 3 | 466s | – | – | 7 | 0 |
| mod_php OFF | 80 | 19 | 4 | 258s | – | 124s | 3 | 0 |
| mod_php ON | 72 | 20 | 4 | 422s | – | 517s | 10 | 0 |
| FPM OFF | 109 | 15 | 4 | **–** | **–** | 75s | 0 | **17** |
| FPM ON | 140 | 15 | 4 | **–** | **–** | 238s | 0 | **16** |

해석:
- **FPM**에서는 파싱 중 fatal(parse_oom 계열)이 워커를 종료시킨다(§2.7 exit 70과 일치). 마스터가 워커를 교체하면서 잔류가 소멸하므로, 이 시퀀스 모델에서 Bug S·P16은 **구조적으로 도달 불가**다. 런타임 fatal(P17)만 워커가 살아남아 재현된다. 같은 이유로 FPM에서는 멈춤도 0건이다.
- **mod_php**는 CLI와 같은 생존 모델이다. Path B 자기 교착 멈춤이 가장 많이 관측됐다.
- P16은 600s 안에 어느 프로파일에서도 재발견되지 않았다. 900s 기준으로는 CLI에서 재발견됐다(§10.9).
- 피드백 ON 열세는 SAPI와 무관하게 유지됐다(§10.9 결론과 일치).

**FlowFusion 브리지** (`linux/flowfusion-bridge.py`, php/flowfusion `87cde41`을 수정 없이 재사용)

준비:
- `prepare.py --no-build`로 시드 23,143개(lint 거부 809개), API 지식 DB를 만들었다.
- php-src 테스트 트리는 원본을 수정하지 않고 사본(`ext/php-src-8.4.4`)을 쓰며, out-of-tree ASAN CLI를 심볼릭 링크로 연결했다.

실행 방식:
- FlowFusion `--generate`로 생성한 융합 프로그램을 **요청 0**으로 실행한다. 같은 프로세스에서 소비자 요청(progress 업로드 / 파일 없는 업로드 / 세션)을 이어 보내고, gdb로 상태를 관측한다.
- 판정은 intra_request(요청 0의 메모리 오류 = FlowFusion 고유 영역) / cross_request / carried_state / clean으로 나눈다.
- exec·네트워크 함수는 차단했다(`disable_functions`, `allow_url_fopen=Off`).

결과 `flowfusion-bridge-20261023T063514-8.4.4-s11`:
- 100개 프로그램, 전략 9종(dataflow / state / declaration 및 연쇄).
- 요청 0 정상 응답 92/100. **판정 100/100 clean**: 요청 간 잔류, 불변조건 후보, 메모리 오류 모두 0.

한계:
- `--INI--` 미적용, FlowFusion의 JIT·opcache 실행 모드 미적용, CLI 서버만.
- 규모가 100개로 작아, FlowFusion 본래의 대규모 단일 요청 퍼징을 대체하지 않는다.
- 요청 간 잔류 관점의 **음성 결과는 스코프 한정**(`not_found`)이다.

**G5 판정:** 프로파일 3종을 같은 기준으로 비교했다(하네스 오류 0, `g5 passed=true`). FlowFusion 생성물을 Stage 1 다중 요청 실행에 연결하고 측정까지 마쳤으므로 **통과**다.

### 10.11 v2 보완 — 1c code-edge 피드백, Stage 4 커버리지 맵·차등 트리아지, 정정 (2026-10-23)

> 앞선 보고("§12.6.5 12단계 전부 실행")는 **과대 표기**였다. Stage 1c code-edge 피드백과 §12.3 Stage 4의 커버리지 맵·차등 트리아지가 빠져 있었다. 이 절에서 그 세 항목을 구현·측정했다.

**1c — code-edge 피드백** (`build.sh` cov flavor, `lifecycle-explore.py --cov`)
- **빌드:** `8.4.4-cov` = asan 빌드 + `-fsanitize-coverage=trace-pc-guard`.
- **수집:** `ASAN_OPTIONS=coverage=1`로 프로세스마다 `.sancov`가 생긴다. CLI 서버는 SIGINT로 정상 종료해야 덤프가 남는다(gdb는 SIGINT를 통과시킨다). ASAN abort로 죽은 프로세스도 덤프된다(스모크: 정상 6,148 / P17 UAF 실행 5,835 edge).
- **피드백:** 새 edge를 코퍼스 편입·가중치에 반영한다. summary에 `code_edge_coverage`를 기록한다.
- **G4 재평가** `explore-g34-20261023T071112-8.4.4`(`--cov`, 600s × ON/OFF × seed 1~3, 동일 hold-out):

| 지표(평균) | ON | OFF |
|---|---|---|
| code edges | 6,901.7 | 6,907.0 |
| 고유 전이 T | 21.3 | 26.0 |
| ASAN 시그니처 | 1.33 | 2.67 |
| 첫 검증 오류까지 | 175s (2/3회만 발견) | 97s (3/3) |

- **결과:** code-edge 피드백을 넣어도 ON 열세는 그대로다(G4 결론 유지).
  - edge는 요청 1개(health)만으로 약 6.1k가 덮이고, 두 쪽 모두 약 6.9k에서 포화된다. 이 시퀀스 공간에서 edge는 요청 조합의 차이를 구분하지 못한다. 상태·시퀀스 조합이 핵심 신호다.
  - G2(루프 폐쇄)는 edge 포함 상태에서도 재확인됐다(on-s1 최대 깊이 5, 재선택 15).

**Stage 4 — 커버리지 맵** (`linux/coverage-map.py`)
- Fuzz Introspector는 LTO·introspector 빌드 파이프라인이 필요해, 같은 목적을 sancov + llvm-symbolizer로 대체했다(대체 사실 명시).
- 대상: §10.11 캠페인 6회, `.sancov` 569개, 고유 edge 6,910, 덮인 파일 208개·소스 줄 5,463.
- **정적 후보 도달**(fault-site-map 후보 줄 + 6줄 창): count_before_fallible **14/44**, init_fallible_destroy **0/5**, global_ptr_request_free **4/7**, refcount_then_fallible **5/13**.
  - 미도달 후보가 다음 정적·동적 우선순위의 공백 목록이다. 예: `zend_hash.c:955-956`(Path A 카운터, mod_php 전용 multipart 형상이라 CLI 문법으로는 미도달), `session.c:1006/1071/1117`(INIT→fallible→DESTROY 창), `basic_functions.c:2310`.
- **요청 경로 함수 커버리지:**

| 파일 | 덮인 함수 / 전체 |
|---|---|
| rfc1867.c | 27/28 |
| php_variables.c | 17/28 |
| session.c | 57/102 |
| var.c | 12/36 |
| var_unserializer.re | 19/29 |
| zend_hash.c | 58/124 |
| basic_functions.c | 11/84 |

**Stage 4 — 차등 트리아지** (`linux/differential-triage.py`, 8.4.4 ↔ 8.4.27, gdb 상태 관측)
- 비교 항목: 단계별 응답, 실패 지점, 요청 시작 진입 시와 **종료 시**의 정규화 상태(소유권·초기화), ASAN, 멈춤.
- 결과: 양성 대조군 5종(Bug S, P16, P17, 탐색기 최소 P17 변형, Path B flock 교착)이 **모두 `residue_not_formed`**, 음성 대조군은 `no_difference`, 문제 0건.
- **정정(판정 명칭):** §8·§10.2·§10.6은 8.4.27의 P16을 "소비 지점 리셋형(MULTIPART_EVENT_START)", P17을 "생산자 잔존 + 소비 차단형(`php_basic_early_rinit`)"으로 기록했다. 실측은 다르다.
  - 8.4.27에서 생산자 요청의 **종료 시점에 이미** `BG(unserialize).level=0`, `data=NULL`, PS 포인터 NULL이다.
  - 8.4.27 unserializer는 `zend_string_falloc(.., fallible)` + `ZEND_HAS_OOM()` 검사 + `zend_mm_delayed_error`(지연 fatal)로 실패 경로를 정상 해제한다. 잔류가 **생기지 않는다**.
  - 조기 리셋(`php_basic_early_rinit`, main.c:1869)은 이 시퀀스들에서 실행될 대상이 없는 **이중 방어 계층**이다.
  - 이에 따라 `ground-truth-eval.py`의 차단 지점 라벨 `consumer_reset`을 근거 없는 메커니즘 명칭으로 보고 중립 명칭 `consumption_absent`로 바꿨다. 메커니즘 귀속은 트리아지 결과로 한다. P15의 `delivery_blocked`는 유지한다.
  - 관측 범위는 CLI 서버다. mod_php·FPM은 같은 코드 경로로 추정되지만 이 트리아지로 직접 관측하지는 않았다.

**정정 — 퍼저 사전 이슈와 원본 소스 트리**
- Phase 5 v1 이래 "사전(dict) 생성 이슈"의 원인을 확인했다. `generate_unserialize_dict.php`는 stdout이 아니라 `__DIR__/dict/unserialize`에 쓴다. 그래서 하네스는 빈 stdout을 실패로 판정했고, 실제 사전은 **원본 소스 트리**(`sources/php-8.4.4/sapi/fuzzer/dict/unserialize`, 미추적 파일 1개, 10-23 10:13 생성)에 남았다.
- 이 파일 때문에 `build.sh`가 "Source modified"로 빌드를 거부했다.
- 조치: 파일을 `evidence/source-tree-stray-20261023/`으로 옮겨 보존했다. 원본 4개 트리는 `git status` 0건이다. 이후로는 생성기 사본을 증적 디렉터리에서 실행하며, 사전 135항목 생성을 확인했다(커밋 `b1a88ea`).

**커밋 단위 정정(2026-10-23, 사용자 승인 후 이력 재작성):** 처음에는 G1·G2와 G3·G4가 각각 하나의 커밋(구 `226060e`, `70d4466`)으로 묶여 있었다. 사용자 승인을 받아 이력을 재작성(force push)해 게이트별 커밋으로 분리했다: G0 `1aa256e` · **G1 `8193340`** · **G2 `f4f48a6`** · 단계 8 `202ca55` · **G3+1f `e3644f4`** · **G4 `33c2403`** · **G5 `103f59b`**. 이후 보완 커밋은 사전 `b1a88ea`, 1c `67e1af5`, 커버리지 맵 `8993b3e`, 트리아지 `901c4f9`, 문서 `eadb02e`·`8c8fcf4`이다. 재작성 전후의 최종 트리는 동일하다(`git diff` 0건). 재작성 전 이력은 로컬 `backup-pre-split` 브랜치에 보존한다.

**남은 한계(명시):**
- 1c 상태 ID는 다음 요소로 구성된다.
  - 소유 요청: carried = 이전 요청에서 본 주소
  - 수명 단계: startup / shutdown
  - 상태 종류: BG serialize/unserialize 레벨·포인터, PS id/mod_data/vars, url_adapt
  - 소비 경로: 액션
- 계획 문구의 **할당·해제 사이트**는 상태 ID에 넣지 않았다. 비충돌 상태에서는 할당 사이트를 얻을 수단(할당기 훅)이 없고, 할당·해제 스택은 ASAN 보고가 있을 때만 시그니처로 쓴다.
- Stage 2의 AST/콜그래프판 후보 열거(Coccinelle 등)는 미구현이다. 정규식 스캐너는 범위·누락 보고까지 보강했고(§10.6), 그 공백은 커버리지 맵으로 보완했다.

### 10.12 v2.1 — 실패-닫힘 판정기로 재도출 (2026-10-23, 계획 §13.3·§13.6-4)

> 이 절은 §10.9~10.11 수치를 **대체**한다. 앞 절 수치는 판정기 결함(Issue #5)이 있던 시점의 값이다. 재도출 증적은 `evidence/rederive-v21-20261023T095350/`에 있다.
> - **출처(R12):** 드라이버 `linux/rederive-v21.sh`. 실효 소스 커밋 `7d08b45`이다. `rederive.json`에는 WSL git의 safe.directory 문제로 `source_sha: unknown`이 기록됐다. 실행 창(09:53:50Z~11:45:40Z) 동안 로드된 파일을 건드린 커밋이 0건임을 `provenance-note.json`으로 확인했다(`reconstruction_valid: true`).
> - 10개 단계 모두 rc=0. G3/G4 배치의 `batch.json`은 6/6 valid다.

**판정기 수정 요약(#5 1~11):**
- P0: `linux/verdicts.py`(자체 테스트 24/24) — 실행 무결성 → replay differential·FlowFusion 3축·triage 증거 칼럼.
- P1·P2: 아래 항목을 각각 고치고 픽스처를 붙였다.
  - G3 인과 사슬
  - ground-truth 관측·추론 분리(15/15)
  - readiness·PID 귀속
  - 배치 rc(`batch-check.py` 7/7, `batch-fixtures.sh` 4/4)
  - sancov 수집 상태와 커버리지 양성 대조
  - 커버리지 맵의 exact/nearby/gap 분리와 바이너리 SHA 검증(7/7)
  - G5 게이트 분리
- 실측 확인: 존재하지 않는 수정 버전에 대한 replay는 `harness_failed`, `extinct=false`, rc 1이다. 구 코드는 `extinct=True`를 냈다.

**재도출 결과와 기존 보고의 관계:**

| 항목 | 기존 보고(§10.9~10.11) | v2.1 재도출 | 실제 결과가 틀렸는가 |
|---|---|---|---|
| ground-truth | 8.4.4 재현 3/3, 8.4.27 소멸 3/3 | 동일(P17 생산자는 이제 unserialize 줄 31 착지까지 요구). 8.4.4·8.4.27 모두 exit 0 | 아니오 |
| G3 재발견 | 판정식: 함수명 히트 | 인과 사슬로 판정(생산자 착지 → RINIT에 닿는 요청 없음 → 귀속된 소비자 ASAN). `signature_only` 0건. 기존 두 배치의 재평가에서도 비율이 그대로 | 아니오(코드 결함만 실재) |
| G3 (`--cov` 재실행, 600s×3) | — | ON: P17 2/3, P16 1/3, Bug S 1/3. OFF: P17 3/3, P16 2/3, Bug S 3/3. 게이트 통과(정답 쌍 제외 + ON에서 P16 또는 P17의 인과 재발견) | — |
| G4 | ON 열세 | ON 열세 재확인: 전이 19.0 대 26.0, ASAN 시그니처 1.33 대 2.67, 첫 발견 206s 대 98s, edge 6,891 대 6,908. 피드백 우위 **미입증**(이 문법·예산 한정) | 아니오 |
| G5 | 통과 | 환경 게이트·비교 게이트 모두 통과. 유효 실행 = 전체 실행(CLI 92/84, mod_php 80/72, FPM 111/142). 모든 실행에 워커 pid 기록. 세 생산자 착지 확인. FPM은 Bug S·P16 미재발견에 ASAN 없는 워커 교체 17건 — §10.10 결론 유지 | 아니오(게이트 산식만 보강) |
| FlowFusion "100/100 clean" | 철회(§13.2) | 수명주기 관측 완료 **99**(정상 90 + 실행 중 fatal 6, 그중 2건은 HTTP 200인데 fatal + 컴파일 오류 4), `consumer_incomplete` 1. 융합 프로그램 정상 실행 96, 그중 clean 95. 요청 간 잔류·메모리 오류 0 | **예, 1건**: 소비자 미실행 프로그램을 clean으로 셌다 |
| 커버리지 맵 "14/44" 등 | "도달" | 정확한 후보 줄 실행 / 근접 줄만 실행 / 공백: count_before_fallible **8 / 6 / 30**(44), init_fallible_destroy **0 / 0 / 5**, global_ptr_request_free **3 / 1 / 3**, refcount_then_fallible **3 / 2 / 8**. 미해석 주소 0%. 바이너리 SHA 일치. "14/44"는 정확 + 근접의 합이었으므로 **도달 수치로 인용하지 않는다** | 표현 과대(수치 자체는 근접 포함으로 정확) |
| 트리아지 `residue_not_formed` | 관측 + 추론 혼합 | 양성 5종 모두 `extinct` / **`validated`**. 근거는 계측 이벤트 차분: 8.4.27 생산자 요청에서만 `php_var_(un)serialize_destroy`가 실행되고(취약 버전은 fatal로 건너뜀), 종료 시점 상태는 `absent_at_observed_shutdown`. 음성 대조군은 `no_difference`. 메커니즘 서술 "fallible 할당 + 지연 OOM"은 여전히 패치 소스에서 나온 추론이다. 검증된 것은 "생산자 컨텍스트가 정리되었다"까지다 | 아니오(명칭 과대 → 관측·추론 분리) |

**R12 재실행 — findings 인용 진단:**
- `linux/diag/pathb-flock-deadlock.py`: 8.4.4에서 자기 교착 재현(`flock` syscall 73, `locks_lock_inode_wait`, CPU 0), 8.4.27은 200 응답. `citable: true`.
- `linux/diag/observer-effect.py`: gdb 있음 2회·없음 2회 결과 동일. `citable: true`.
- §10.7의 인라인 코드 결과와 일치한다.

**판정기 결함으로 발견·수정한 추가 오류:**
1. 중단된 업로드는 `php_request_startup`에 닿지 않는데, 이를 관측기 실패로 처리해 CLI 유효 실행이 절반으로 집계되던 결함.
2. 재도출 증적의 커밋 해시가 미기록된 것(WSL git safe.directory).

둘 다 수정해 커밋했다(`a1a7ef1`).

## 11. Phase 6 — Historical Corpus·CoreGuard (2026-10-23, 계획 §13.4·§13.5)

> v2(§10)와 구분된 절이다. 원칙: 과거 기록은 **취약점 목록이 아니며**, 재현 실패는 안전 판정이 아니다. 판정기는 v2.1 fail-closed 계열이고, 모든 증적에 출처(R12)를 기록한다.

### 11.1 H0·H1 — 코퍼스 확보와 원천 검증

- **H0:** 사용자 제공 원조사 문서를 수정 없이 `docs/corpus/php-memory-safety-2016-2026.md`(58건)로 넣었다.
- **H1:** `linux/corpus/verify-corpus.py`로 원천 63건을 조회했다. 조회 실패 0, 문서 기재 상태와의 불일치 0이다(문서가 같은 날 작성됨). R24만 "확인 필요"에서 closed/completed로 정리됐다.
- **기록 유형:** fixed 33 / open 14 / advisory 5 / 설계 논의 3 / duplicate 1 / wontfix 1 / unmerged design 1. *(2026-10-24 정정, #4 H1: `fixed 33`은 원천 상태 자동 분류 — 수정 확인 아님. 재분류: `closed_resolution_unverified 32` + `fix_claimed 1`. `fixed_verified`는 별도 확인 필요.)*
- 결과 표: `docs/historical-corpus.md`.

### 11.2 H2.5 — 현재 탐색기 도달성 (데스크 분류)

`linux/corpus/reachability.json`. 기록 본문을 근거로 분류했으며, H2에서 사례별로 확정한다.

| 분류 | 건수 | 비고 |
|---|---|---|
| reachable_now | 3 | R52·R53(2026 CVE 2건), R57(hard limit `_exit(137)` 회귀) |
| needs_php_code | 24 | 사용자 클래스·소멸자·에러 핸들러·GC/Fiber |
| needs_extension | 14 | soap 6, mbstring 2, exif 2, xmlreader, filter, simplexml, opcache, pgsql |
| needs_payload_grammar | 4 | unserialize 조작 페이로드 |
| needs_oracle | 2 | 임시 파일 누수(디스크 DoS), 파서 bailout 누수 |
| needs_sapi | 1 | FPM master |
| out_of_scope | 2 | xmlrpc(8.0에서 제거), 7.3 전용 |
| design_record | 8 | #3 입력 |

→ 현재 10개 액션 문법으로 hold-out을 적용하면 대부분 **탐색 실패가 아니라 도달 불가**를 재게 된다. 사용자 지적과 같은 결론이며, H2.5 확장을 H3보다 먼저 한다.

### 11.3 H2 — 독립 재현 1차 (`linux/corpus/run-repro.py`)

**방법:**
- 재현 코드는 원천에서 원문 그대로 받아 커밋했다(`linux/corpus/repro/`). 실행 전에 읽었다.
- CLI `php -n`, exec·네트워크 함수 차단, 임시·세션 경로는 실행 디렉터리 안으로 제한했다.
- 증적: `evidence/corpus-h2-20261023T131635-asan`(`citable: true`).

| 기록 | 8.4.4 | 8.4.27 | 해석 |
|---|---|---|---|
| **R46** PR #22710 (`zend_hash_clean()` 중 소멸자 bailout, PR 미병합) | **재현**(ASAN SEGV, `php_var_serialize_intern` ← `ps_srlzr_encode_php`) | **재현**(같은 시그니처) | 공개된 미수정 경로가 **현행 수정 릴리스에서도 재현**된다. `session_unset()` 중 E_USER_ERROR bailout 뒤 이미 소멸된 슬롯을 세션 인코더가 다시 소비한다. 공식 패치(8.4.27)가 덮지 않는 **부분 정리 실패 원자성** 부류로, CoreGuard Phase 2 hold-out 후보다. 재현 입력은 이미 공개 PR에 있으므로 D1 신고 대상이 아니다 |
| R26 GH-12073 (OOM 중 closure 부분 초기화) | 미재현 | 미재현 | 2023-09 수정. 두 빌드 모두 수정 후 버전이라 기대와 일치하며, 수정 전 빌드가 필요하다 |
| R35 GH-16726 (에러 핸들러 교체 UAF) | 미재현 | 미재현 | 원보고는 fuzzer SAPI 실행 경로 기준이다. 미재현은 안전 판정이 아니다 |
| R23 GH-10026 (SOAP 후 gc_protect 잔류) | capability_gap(soap) | capability_gap | H2.5 `asanext` 빌드 후 재실행한다. 원 이슈 버전은 외부 호스트에 접속하므로 쓰지 않고, PR 테스트(127.0.0.1)만 쓴다 |
| R49 GH-24361 (opcache_compile_file 후 GC 보호 잔류) | capability_gap(opcache) | capability_gap | 위와 같음 |
| R18 #79760 (get_gc OOM 뒤 GC 정리 불일치) | no_reproducer | — | 원천에 스크립트가 없다(Laravel 테스트 중 관측). 재현 코드를 구성해야 한다 |

**H2 2차 (H2.5 확장 빌드 `asanext`, 2026-10-23):**
- 증적: `evidence/corpus-h2-20261023T132556-asanext`, R49 재판정 `…T132648-asanext`. 둘 다 `citable: true`.
- 빌드: asan + opcache·soap·XML 계열·filter·exif·mbstring(`--disable-mbregex`)을 8.4.4와 8.4.27 모두 만들었다.
- 사례 37건: 스크립트 있음 28, `no_reproducer` 8, `excluded_weaponized` 1.
  - R54(GH-24481)는 보고의 코드가 실제 앱 가젯 체인 기반의 무기화된 phar 페이로드뿐이라 **실행하지 않았다**(안전 경계).

| 기록 | 패턴 | 8.4.4 | 8.4.27 | 근거·해석 |
|---|---|---|---|---|
| R23 GH-10026 | SOAP 예외 회복 후 `gc_protect` 잔류 | **재현** | **재현** | 출력 `GC Runs: 3`이 SOAP 실패 뒤 증가하지 않는다(GC 정지). 공개 미해결 이슈 |
| R49 GH-24361 | opcache 컴파일 오류 회복 후 GC 보호 잔류 | **재현** | **재현** | protected-after `bool(true)`, 이후 `gc_collect_cycles()` 0. 1차 오라클은 컴파일 결과를 읽은 결함이 있어 실제 출력으로 확인하고 수정했다(R5) |
| R46 PR #22710 | `zend_hash_clean` 중 bailout → 이중 정리 | **재현** | **재현** | ASAN SEGV `php_var_serialize_intern` ← `ps_srlzr_encode_php`. 수정 PR 미병합 |
| R51 GH-24455 | lazy object reset + 소멸자 재진입 | **재현** | **재현** | `zend_mm_panic` ← `zend_mm_get_next_free_slot`(Zend 힙 무결성 검출). 공개 미해결 이슈 |
| R55 GH-24488 | SimpleXML GC 이중 해제 | 미재현 | **재현** | **8.4.27 긴급 릴리스가 들여온 회귀** — 기록 내용과 일치 |
| R41 GH-20352 | 출력 핸들러 오류 해제 중 `ob_start` 재진입 | **재현** | 미재현 | 2025-11 수정이 8.4.27에 포함됐다 — 수정 시점과 일치 |
| R42 GH-21499 | RecursiveArrayIterator raw 버킷 포인터 | **재현**(디버그 assertion `refcount > 0` 실패, SIGABRT) | 미재현 | 2026-03 수정 — 수정 시점과 일치 |
| 나머지 21건(R01~R04, R06, R07, R13, R14, R17, R19, R24~R27, R32~R35, R38, R47, R50) | — | 미재현 | 미재현 | 대부분 8.4.4 이전에 수정된 기록이다. 수정 전 빌드가 없어 **수정 효과를 이 랩에서 확인하지 못한다**. 미재현은 안전 판정이 아니다 |

**의미:**
1. 현행 공식 수정 릴리스(8.4.27)에서 공개 미해결 경로 5건이 재현된다(GC 보호 잔류 2, 정리 중 bailout 1, 재진입 1, 회귀 1). 모두 이미 공개된 기록이라 D1 대상이 아니며, **CoreGuard "공식 패치 밖 새 실패 경로" 평가의 실재 후보**다.
2. 이 재현은 CLI 단일 스크립트 기준이다. HTTP 요청 수명주기 탐색기(H2.5 PHP 코드 액션)의 도달성은 별도 과제다.
3. 할당기: `USE_ZEND_ALLOC=1`(Zend MM)로 실행했다. 일부 오류는 ASAN 대신 Zend 힙 무결성 검사(`zend_mm_panic`)나 디버그 assertion으로 검출됐다.

### 11.4 H3 — OFF 기준선: 융합 액션으로 8.4.27 탐색 (`linux/explore-h3.sh`, `02731fb`)

> **[무효 — §11.5에서 대체]** 튜닝 보정 중에 하네스 결함이 확인됐다. `fused` 액션이 상태 줄만 받고 연결을 닫아서, 프로그램이 다음 출력을 쓰려 할 때 `php_handle_aborted_connection`이 bailout하며 **첫 출력 이후의 코드가 실행되지 않았다**. 아래 수치는 "융합 프로그램이 대부분 잘린 상태"의 결과이므로 기준선으로 쓰지 않는다. 증적 디렉터리는 기록으로 남긴다. 수정은 `852770e`, 재측정은 §11.5에 있다.

**방법:**
- 빌드 8.4.27 `asanext`, CLI 서버. FlowFusion 풀 200개(시드 11, 8.4.27 php-src 테스트에서 생성, generator rc 0)를 `fused` 액션으로 시퀀스 단계에 넣었다(H2.5).
- 피드백 OFF(무작위), 시드 1·2·3, 각 600초. 샌드박스: exec·네트워크 함수 차단, `allow_url_*` Off, 실행 디렉터리를 cwd로 고정.
- 증적: `evidence/explore-h3-20261023T133235-8.4.27`(batch ok, 실패 0, `citable: true`).

| 시드 | 실행 | integrity `executed` | 융합 단계 포함 시퀀스 | 고유 프로그램 | 고유 키 S/T/F | 발견 |
|---|---|---|---|---|---|---|
| 1 | 113 | 113 | 26 | 29 | 2/18/6 | 0 |
| 2 | 109 | 109 | 26 | 25 | 2/20/8 | 0 |
| 3 | 100 | 100 | 21 | 21 | 2/17/5 | 0 |

- 융합 단계 82개: 응답 200이 75, 500이 7. 500 7건은 모두 PHP 오류(미정의 인터페이스, `__debugInfo` 반환형 등)로 설명되며 워커는 살아 있었다. 200 중 5건은 런타임 fatal을 200으로 낸 경우다.
- ASAN 보고·워커 사망·정지: **0**. 알려지지 않은 시그니처가 없으므로 D1 대상도 없다.

**hold-out 재발견: 0/3(R23·R46·R51).**

**해석(관측 범위 안에서):**
1. 예측된 결과다. 풀은 8.4.27 php-src 테스트에서 온 프로그램이라 미해결 이슈(hold-out)의 재현 구문을 포함하지 않는다(`fused-pool.py` 설계 조건). 따라서 이 결과는 "무작위 탐색 + 현행 테스트 융합"이 hold-out 부류에 닿지 못한다는 **기준선**이지, 8.4.27이 해당 부류에 안전하다는 근거가 아니다(H2에서 세 건 모두 재현됨).
2. 처리량이 병목이다. 30분에 융합 단계 82개, 풀의 약 35%만 한 번 이상 실행됐다. gdb 관측기 비용이 실행당 대부분을 차지한다.
3. ON 재설계(계획 §13.3a)는 이 기준선과 비교한다. 재설계는 튜닝 세트(R49·R55) 부류의 상태 신호(GC 보호 플래그, bailout 회복, 소멸자 재진입)만으로 조정하며, hold-out은 비교 1회에만 쓴다.

### 11.5 H3 — ON 재설계(`--feedback state`)와 튜닝 세트 보정 (계획 §13.3a)

**재설계(`3937243`~`e1d1f45`):** 보상은 code-edge 수가 아니라 상태 신호에 준다. 새 키가 생기면 가중치를 더한다.

| 키 | 신호 | 가중치 |
|---|---|---|
| G | (a) 요청이 **정상 종료**(융합 프로그램이 반환, 라우터의 `LAB-FUSED-END`)했는데 shutdown 시점에 GC가 protected/active/disabled 상태. (b) shutdown 밖에서 `zend_mm_delayed_error`(메모리 한도)가 GC protected 상태에서 발생 | 4 |
| R | 오류 복구: 실패 지점이 기록됐는데 2xx로 끝났고 워커가 살아 있음 | 4 |
| A | 귀속된 ASAN 보고 | 4 |
| S(carried) | 요청 간 소유권 전이(이전 요청 포인터 잔류) | 3 |
| H / 기타(S·T·F) | 정지 / 그 밖의 새 상태·전이 | 2 / 1 |

- 관측기에는 `'zend_gc.c'::gc_globals`(enabled·active·protected·runs)를 추가했다. `_zend_bailout`·`zend_mm_delayed_error`는 이벤트로 기록한다(GC 보호 플래그, `EG_FLAGS_IN_SHUTDOWN`, bailout 호출 프레임 6개).
- 재진입 신호(소멸자·콜백 중 상태 변경)는 **구현하지 않았다**. 범용 지점(`zend_objects_destroy_object` 등)에 중단점을 걸면 gdb 비용이 너무 크다. hold-out R51과 같은 특정 함수에 거는 것은 지식 누출이다(Phase 0 §3). 미구현 공백으로 남긴다.

**튜닝 세트로만 보정(`linux/explore-tune.sh`, 풀 = R49·R55 재현 코드, `fused-pool.py --cases`는 hold-out 기록을 거부한다):**

| 반복 | 관측 | 조치 |
|---|---|---|
| 1 | shutdown 시점 `gc_protected=1`이 `parse_oom`·`runtime_oom`에서도 나왔다 | 8.4.27 `_zend_bailout()`이 항상 `gc_protect(1)`을 호출한다(`Zend/zend.c:1262`). 종료형 fatal 뒤의 보호 상태는 정상이므로, 정상 종료한 요청에만 G를 준다 |
| 2 | R49가 정상 종료로 집계되지 않았다 | 반복 3·4에서 원인을 찾았다 |
| 3 | "보호 상태에서 두 번째 bailout" 신호는 lab 앱 `upload`에서도 났다. 프레임을 보니 `soap_error_handler`가 잡아서 다시 던지는 경우와, 연결이 끊긴 뒤 쓰기(`php_handle_aborted_connection`)였다 | 재개와 재던짐을 구분하지 못하므로 이 신호를 폐기했다. 대신 "GC 보호 중 메모리 한도"를 쓴다 |
| 4 | R49 실행이 1.2초 만에 `php_handle_aborted_connection` bailout으로 끝났다 | **하네스 결함:** `fused` 요청이 본문을 읽지 않고 연결을 닫았다. 본문을 끝까지 읽도록 고쳤다(`852770e`). §11.4 OFF 기준선은 무효다. lab 앱 액션에서는 같은 프레임이 관측되지 않았다(작은 단일 출력) |
| 5 | R49 → `G:fused|gc_protected`, `R:fused|gc_protected`(정상 종료, `completed=true`). R55 → `A:heap-use-after-free:zend_gc_collect_cycles>zif_gc_collect_cycles>…` | 두 튜닝 신호가 의도대로 발생한다 |

- 증적: `evidence/explore-tune-20261023T143726-8.4.27`(반복 5, `citable: true`). 반복 1~4 디렉터리는 보정 기록으로 남긴다.
- 보정 중에 hold-out 스크립트는 실행하지 않았다. 신호는 부류 수준(정상 종료 후 GC 보호 잔류, 보호 중 메모리 한도)으로 정의했다. 단, R23(hold-out)도 같은 부류이므로 **G 신호는 R23 부류에 대해 독립적이지 않다**. R46·R51 부류에 대응하는 신호는 A뿐이다. 평가 보고에 이 한계를 적는다.

### 11.6 H3 — OFF vs state 비교 (8.4.27 `asanext` + opcache, 융합 풀 200, 3시드 × 600초)

- 드라이버 `linux/explore-h3.sh`(`2d757ad`), 보고 `linux/h3-report.py`(`73f42a7`). 증적 `evidence/explore-h3-20261023T144334-8.4.27`(batch ok, 6/6 rc 0, 모든 실행 `executed`), 보고서 `h3-report.json`.

| 모드 | 실행 | 융합 단계 | 정상 반환 | 고유 프로그램 | 새 G | 새 R | 새 A | hold-out 재발견 | 미지 시그니처 |
|---|---|---|---|---|---|---|---|---|---|
| OFF | 322 | 82 | 67 (82%) | 64 | 0 | 4 | 0 | **0/3** | 0 |
| state v1 | 409 | 139 | 49 (35%) | 28 | 0 | 4 | 0 | **0/3** | 0 |

**해석:**
1. 본문 읽기 수정(§11.5) 뒤 OFF에서는 융합 프로그램의 82%가 정상 반환한다. §11.4의 잘린 실행이 수정됐다.
2. 두 모드 모두 메모리 오류·GC 부류 신호·hold-out 재발견이 없다. 풀(8.4.27 php-src 테스트 융합)이 이 부류에 닿지 못한다는 기준선이다. 8.4.27이 안전하다는 근거는 아니다(H2에서 세 건 모두 재현됨).
3. **state v1은 다양성에서 OFF보다 나쁘다.** 고유 프로그램이 64에서 28로 줄었다. 스케줄러가 "fatal인데 HTTP 200"인 프로그램(예: 선언 비호환 컴파일 fatal)에 R 키를 주고 그 시퀀스를 반복 변이했다. 그런 프로그램은 실행이 이어진 것이 아니라 **종료형 fatal**이다. 원인은 R 신호 정의 오류다. hold-out을 보고 찾은 것이 아니라 스케줄 기록(`scheduler.jsonl`, 프로그램별 빈도)에서 진단했다.
4. 조치(`581e842`, state v2): 융합 프로그램의 R은 정상 반환(`LAB-FUSED-END`)을 요구한다. 같은 풀(`POOL=` 재사용)로 state만 다시 측정한다(§11.7).

### 11.7 H3 — state v2 재측정과 결론

- 증적 `evidence/explore-h3-20261023T154514-8.4.27`(같은 풀: `pool.json` 바이트 동일, 3/3 rc 0, 423 실행 모두 `executed`).

| 모드 | 실행 | 융합 단계 | 정상 반환 | 고유 프로그램 | 새 G/R/A | hold-out | 미지 시그니처 |
|---|---|---|---|---|---|---|---|
| OFF (§11.6) | 322 | 82 | 67 | 64 | 0/4/0 | 0/3 | 0 |
| state v1 (§11.6) | 409 | 139 | 49 | 28 | 0/4/0 | 0/3 | 0 |
| state v2 | 423 | 98 | 36 | 21 | 0/0/0 | 0/3 | 0 |

**결론:**
1. R 정의를 고쳐도 다양성은 회복되지 않았다(21). 축소의 원인은 신호가 아니라 **변이 스케줄러 구조**다. 부모 시퀀스를 변이하면 융합 단계의 프로그램 번호가 `param` 변이로만 바뀐다. OFF는 매번 새 시퀀스를 뽑는다. 풀 크기가 200인 공간에서는 프로그램 다양성이 곧 탐색 범위다.
2. 이 풀에서 state 피드백은 OFF보다 나은 점이 관측되지 않았다. 계획 §13.3a대로 **OFF를 기준선으로 유지**하고, G4는 계속 보류한다.
3. hold-out 3건은 두 모드 모두 0/3이다. H3의 답은 "현재 탐색기 + 현행 테스트 융합으로는 hold-out 부류에 도달하지 못한다"이다. 도달하려면 부류를 겨냥한 입력 생성(H2.5 남은 과제: payload 문법, bailout 유발 + 회복 + GC 관찰을 결합한 구성)이 필요하다. 그 생성기는 hold-out이 아니라 튜닝 세트와 부류 정의로만 만든다.
4. 신호 자체(G·A)는 튜닝 세트에서 작동함을 확인했다(§11.5). 실패의 원인은 신호가 아니라 도달이다.
5. 추가 조정은 하지 않는다. 같은 풀에서 거듭 조정하면 그 풀에 과적합되고, hold-out 비교의 의미가 약해진다.

### 11.8 CoreGuard — B 성능 기준선과 Phase 2b 개발 검증 (계획 §13.5, 사전 등록 v1)

**B 성능 기준선**(`linux/coreguard/perf-baseline.py`, 빌드 `8.4.27-normalext` = release + asanext 확장 집합, Apache event + proxy_fcgi → php-fpm static 4, opcache on, docroot는 ext4 사본, ab n=5000 c=8 × 3회). 증적 `evidence/coreguard-perf-20261023T162420-8.4.27-normalext`(`citable: true`):

| 워크로드 | req/s(중앙값) | p50 ms | p95 ms | 워커 RSS 최대 KB |
|---|---|---|---|---|
| health | 9,549 | 0.77 | 1.22–1.27 | 11,540 |
| session | 6,275 | 0.84–0.96 | 1.52–2.09 | 11,700 |
| unser_small | 9,566 | 0.77–0.78 | 1.21–1.24 | 11,764 |
| upload_small | 7,258 | 0.96–1.11 | 1.49–2.02 | 12,716 |
| `Zend/bench.php`(CLI, opcache 없음) | Total 0.410–0.411 s | | | |

- session은 반복마다 8,083 → 6,275 → 6,061로 떨어진다. 세션 파일이 누적되기 때문으로 보이며, C도 같은 조건에서 비교한다. 이 수치는 이 호스트(WSL2, 6코어)에서의 **상대 비교용**이다.

**Phase 2b(설계 `docs/coreguard/phase2b-design.md`, 패치 `0001-phase2b-gc-resume-guard.patch`, 빌드 `8.4.27-coreguard-asanext` = 실험 사본 + 패치, 원본 소스 변경 0):**
- 개발 검증 `linux/coreguard/phase2b-tests.py`, 증적 `evidence/coreguard-p2b-tests-20261023T162403-asanext`(`citable: true`): **30/30 통과**, hold-out 실행 0.

| 테스트 | B | disabled | observe | enforce |
|---|---|---|---|---|
| T1 R49(튜닝) | GC 정지(`protected=true`, collected 0) | B와 동일 | 이벤트 + B와 같은 출력 | 이벤트 + 11행(순환 생성 루프 시작)에서 CoreGuard E_ERROR로 종료, 메모리 증가 전 |
| T2 정상 순환 + GC | 정상 | 동일 | 이벤트 없음 | 이벤트 없음 |
| T3 종료형 fatal | — | 동일 | 이벤트 없음 | 이벤트 없음 |
| T4 잡힌 bailout 뒤 순환 없는 코드 | `protected=true` 잔류 | 동일 | **이벤트 없음** | 이벤트 없음 |

- ASAN 보고는 모든 모드에서 0이다. disabled의 stdout은 4건 모두 B와 같다.
- T4는 탐지 한계를 확인한다. 보호가 남아 있어도 루트 거부가 없으면 이벤트도 없다(피해도 아직 없다).
- 다음: C(`coreguard-normalext`) 성능과 B/C PHPT 비교, 그다음 사전 등록 §6-4 hold-out 1회 평가(3모드 × 3반복).

### 11.9 CoreGuard Phase 2b — v1 → v2, 호환·성능, hold-out R23 1회 평가

**v1 PHPT(enforce) 결과 → v2 수정(`442eb10`):**
- v1은 B 대비 회귀 35건이었다(SOAP 20, Zend 13, SimpleXML 2). Zend의 `oom_*`·`new_oom` 실패는 **오탐**이었다. 8.4.27 지연 OOM 경로(`zend_alloc.c:3669`의 `zend_try/zend_catch`)와 `soap_error_handler`는 bailout을 잡았다가 **다시 던지는데**, 그 사이에 루트 거부가 일어난다. 사용자 코드는 재개되지 않는다. 또 stderr 이벤트 줄 자체가 PHPT 출력을 바꿨다.
- v2: 루트 거부는 검사를 **무장만** 하고, 검사는 다음 opcode 경계(VM interrupt)에서 한다. 다시 던지는 경로에서는 opcode가 실행되지 않으므로 이벤트가 없다. `COREGUARD_LOG=<file>`을 추가했다.

**v2 검증**(두 C 빌드 모두 패치 SHA `80c07a30…`, `build-manifest.json`):

| 항목 | 결과 | 증적 |
|---|---|---|
| 개발 테스트(튜닝 R49 + 합성) | 30/30 | `coreguard-p2b-tests-20261023T163832-asanext` |
| PHPT observe(7,922 테스트) | **B 대비 회귀 0**. 이벤트 22건(재개 사례) | `coreguard-phpt-20261023T164403-…`, `logs/cg-events-phpt-observe.log` |
| PHPT enforce | **회귀 19건**(SOAP 16, `arginfo_zpp_mismatch*` 2, session `gh12504` 1). 모두 잡힌 bailout 뒤 실행이 실제로 재개되는 테스트이며, enforce가 그 요청을 끝냈다 | `coreguard-phpt-20261023T164426-…` |
| 성능(req/s 중앙값 / p95 ms) | B: health 9,078/1.27, session 6,016/2.68, unser 9,312/1.28, upload 7,166/1.60. C disabled·observe·enforce 모두 B의 반복 간 변동 안이다(예: B session 6,016~7,133). `bench.php` 0.405~0.428 s | `coreguard-perf-*-8.4.27-coreguard-normalext-{disabled,observe,enforce}`, `…-8.4.27-normalext` |

**hold-out R23 1회 평가**(사전 등록 v1.1 §6a, `linux/coreguard/holdout-eval.py --cases R23`, 증적 `evidence/coreguard-holdout-20261023T164640`, `citable: true`, 목록 SHA 일치):

| 모드 | 반복 3회 판정 | 관측 |
|---|---|---|
| B | harm 3/3 | SOAP 실패 뒤 `GC Runs: 3` 고정 |
| disabled | `not_protected` ×3 | B와 같은 출력 |
| observe | `detected_only` ×3 | 이벤트 기록, GC 정지는 그대로 |
| enforce | `worker_contained` ×3 | 이벤트 뒤 25행(다음 순환 생성)에서 CoreGuard E_ERROR, GC 정지 전, ASAN 0 |

**판정(Issue #3 Go/No-Go 기준):**
1. **`prevented_before_invalid_access`는 0이다.** enforce는 피해(GC 정지) 전에 요청을 끝냈지만, 유효 요청이 유지되지 않았으므로 성공으로 세지 않는다(v1.1 규칙).
2. **observe: Go(탐지 전용).** 회귀 0, 성능 영향은 측정 노이즈 안이다. hold-out R23에서 3/3 탐지했다. 분류는 `detect-only`다.
3. **enforce: No-Go(기본 활성화 불가).** PHPT 19건 회귀다. 상류(PR #24338 테스트)가 GC를 켠 채 계속하길 기대하는 SOAP WSDL 오류 같은 정상 흐름도 끝내 버린다. 가용성 비용이 크다.
4. **독립성 한계:** R23은 튜닝 R49와 같은 계열이다. 이 결과는 "같은 부류의 다른 진입점(opcache → soap)으로 일반화된다"는 약한 증거다. 새 부류의 보호를 입증한 것은 아니다.
5. R46·R51은 아직 C에서 실행하지 않았다(v1.1: 해당 Phase가 끝날 때 1회).

### 11.10 CoreGuard Phase 2 — 할당 실패 원자성 분석 (8.4.27)

**정적:** `linux/fault-site-map.py --src sources/php-8.4.27`(11/11 파일, 21,377행, `scope_complete`). 증적 `evidence/fault-site-map-20261024T073514`. 후보 수(8.4.4 → 8.4.27): count_before_fallible 44 → 35, init_fallible_destroy 5 → 1, global_ptr_request_free 7 → 7, refcount_then_fallible 13 → 13, reentrancy 0 → 0. 정규식 휴리스틱이므로 가설이며 판정이 아니다.

**동적:** `linux/coreguard/phase2-fault-sweep.py`(`80dd83d`, `9c0f471`). B = 8.4.27-asanext, 추적 할당기, `ZEND_MM_MAX_ALLOCS=N`으로 N번째 할당을 실패시켰다. 워크로드는 자료구조 부류별 합성 코드 10종이다(hold-out·튜닝 재현 코드는 쓰지 않음). N은 1~300을 모두, 그 뒤는 7 간격으로, 정상 완료가 25회 이어질 때까지 올렸다. 주입 없는 대조 10/10 정상. 증적 `evidence/coreguard-p2-sweep-20261023T223614-8.4.27-asanext`(`citable: true`):

| 워크로드 | 실행 | 마지막 OOM N | 메모리 오류 | 중간 정상 완료 | 기타 |
|---|---|---|---|---|---|
| unserialize_nested | 300 | 264 | 0 | 0 | 0 |
| unserialize_refs | 300 | 205 | 0 | 0 | 0 |
| session_codec | 305 | 280 | 0 | 0 | 0 |
| array_ops | 374 | 643 | 0 | 0 | 0 |
| string_ops | 351 | 482 | 0 | 0 | 0 |
| json_codec | 300 | 230 | 0 | 0 | 0 |
| objects_dtor | 338 | 391 | 0 | 0 | 0 |
| simplexml_dom | 339 | 398 | 0 | 0 | 0 |
| mbstring | 300 | 168 | 0 | 0 | 0 |
| var_export_closure | 336 | 377 | 0 | 0 | 0 |

- 첫 실행(`…T223509`)은 종료 규칙이 "정상 완료 3연속"이라 일부 워크로드가 300에서 멈췄다. 25연속으로 바꿔 다시 측정했고, 위 표는 두 번째 실행이다. 두 실행 모두 메모리 오류는 0이다.

**해석:**
1. 이 10개 표면에서는 **모든 주입 지점의 실패가 지연 OOM fatal로 끝났다.** fallible NULL을 받고 조용히 계속한 경우(중간 정상 완료)도 0이다. 8.4.27의 fallible 할당 + `ZEND_HAS_OOM` 지연 오류가 할당 실패를 요청 종료로 바꾼다.
2. 따라서 계획 §13.5 Phase 2(prepare → validate → commit)는 **이 범위에서 공식 수정과 중복된다.** 측정할 추가 효과가 없으므로 구현하지 않는다(No-Go, 근거: 위 표). 300 이후는 표본 추출(1/7)이라 그 구간의 단일 지점은 시험되지 않았을 수 있다.
3. R46(정리 루프 중 bailout → 이중 정리)은 할당 실패가 아니라 **소멸자 bailout의 원자성** 문제라 이 분석의 대상이 아니다. 이 부류의 보호는 Phase 3(격리)에서 다룬다. R46은 원인과 수정 PR 접근을 이미 알고 있는 사례라, 어떤 설계로도 독립적인 성공 근거가 되기 어렵다(Phase 0 §3). 이 한계를 설계 문서에 먼저 적는다.

### 11.11 CoreGuard Phase 1·3, 최종 C 측정, hold-out R46·R51 1회 평가

**구현(원본 소스 변경 0, 실험 사본 + 패치):**
- Phase 3 격리(`docs/coreguard/phase3-design.md`, 패치 0002): 사용자 소멸자 안에서 bailout이 나면 `poisoned`. observe는 기록만 한다. enforce는 더 이상 정리하지 않고 `_exit(70)`.
- Phase 1 잔류 탐지(`docs/coreguard/phase1-design.md`, 패치 0003): `php_basic_early_rinit()` 진입 시 BG(serialize/unserialize) 잔류를 기록하는 observe 전용 가드다. hold-out이 없어 성공은 주장하지 않는다.

**최종 C(패치 0001~0003) 측정** — 커밋된 드라이버 `linux/coreguard/measure-c.sh`(`2665b8e`), 증적 `evidence/coreguard-measure-20261023T225209`:

| 항목 | 결과 |
|---|---|
| 개발 테스트 | Phase 1 4/4(gdb로 잔류를 주입한 양성 대조 포함), Phase 2b 30/30, Phase 3 38/38 |
| 회귀 대조: 8.4.27 수명주기 탐색 OFF + 결함 주입, observe, 600초 | 102 실행 모두 `executed`, 발견 0, **가드 이벤트 0**(잔류·GC·소멸자) |
| PHPT observe | 회귀 0. 이벤트: Phase 2b 22, Phase 3 2, Phase 1 0 |
| PHPT enforce | 회귀 19건, 목록은 Phase 2b 단독(§11.9)과 같다. Phase 3 enforce로 늘어난 회귀는 없다 |
| 성능(같은 실행 안의 B 대비) | C disabled·observe·enforce 모두 B의 반복 간 변동 범위 안이다(health 7.4k~9.4k, B 7.7k~8.4k). FPM 워커 종료 0. 반복 2개(observe health 1회, B upload 1회)는 ab 출력에서 req/s를 읽지 못해 `degraded`로 표시됐다. 실패 요청·2xx 아닌 응답은 0이다(원인 미상, 이후 ab 출력을 저장하도록 수정함) |

- 앞선 v3 측정(패치 0001+0002, §11.9 이후)은 스크래치 래퍼로 커밋된 스크립트를 순서대로 부른 것이다. 모드가 요약에 기록되지 않아 R12 기준으로 **인용하지 않는다.** 위 최종 측정이 그 측정을 대체한다.

**hold-out 1회 평가**(사전 등록 v1.1, `holdout-eval.py --cases R46 R51`, 증적 `evidence/coreguard-holdout-20261023T231409`, `citable: true`):

| 사례 | 모드 | 판정(3회) | 관측 |
|---|---|---|---|
| R46 실패 원자성 | B | harm 3/3 | ASAN SEGV `php_var_serialize_intern ← ps_srlzr_encode_php` |
| | disabled | `not_protected` ×3 | B와 같음 |
| | observe | `detected_only` ×3 | 이벤트 뒤 같은 SEGV |
| | enforce | `worker_contained` ×3 | 이벤트 뒤 rc 70, **세션 인코더 진입 전 종료, ASAN 0** |
| R51 재진입 | B | harm 3/3 | `zend_mm_panic ← zend_mm_get_next_free_slot` |
| | disabled·observe·enforce | `not_protected` ×3 | 이벤트 없음. bailout 없이 일어나는 재진입이라 가드 대상이 아니다(설계 §5 예상과 같음) |

### 11.12 CoreGuard Phase 4 — 할당기 비교 (release 빌드, hold-out 미사용)

`linux/coreguard/phase4-allocators.py`(`679afa1`), 증적 `evidence/coreguard-p4-allocators-20261023T231433`, 구성마다 10회:

| 사례(빌드) | ZendMM | glibc | Scudo | Scudo + GWP-ASan(rate 1) |
|---|---|---|---|---|
| R55 SimpleXML GC 이중 해제(8.4.27-normalext) | 검출 10(`zend_mm_heap corrupted`) | 검출 9(`free()`), 미검출 SEGV 1 | 검출 10(`Scudo ERROR`) | 검출 10 |
| R41 출력 핸들러 재진입(8.4.4-normal) | 조용히 지나감 6, 검출 4 | 미검출 SEGV 10 | 미검출 SEGV 10 | 미검출 SEGV 10 |
| R42 raw 버킷 포인터(8.4.4-normal) | 조용히 지나감 10 | 조용히 지나감 10 | 조용히 지나감 10 | 조용히 지나감 10 |
| `bench.php` Total(s) | 0.43 | 0.44 | 11.4 | 11.5 |

**해석:**
1. **이중 해제(R55)는** 세 할당기가 모두 결정적으로 잡는다. ZendMM도 힙 검사로 잡는다.
2. **잘못된 접근이 할당기 경계를 넘지 않는 경우(R41·R42)는** 어느 할당기도 보고하지 못한다. R42는 release 빌드에서 **완전히 조용하다**(디버그 빌드는 assertion으로 잡음). R41은 ZendMM에서 비결정적이다.
3. GWP-ASan(rate 1, 동시 512개)은 이 사례들에서 Scudo 기본값보다 더 잡은 것이 없다. 샘플링 검출은 보장이 아니다.
4. Scudo 기본 옵션은 이 호스트에서 `bench.php`가 약 26배 느렸다. 옵션을 조정하지 않은 측정이므로 Scudo의 일반 성능 평가로 쓰지 않는다.
5. 결론: 할당기 교체는 **이중 해제류에는 검출을 주지만, 엔진 논리 수준의 상태 오류(R41·R42·R46·R51 부류)에는 보장을 주지 않는다.** CoreGuard의 불변조건 가드와 대체 관계가 아니다. 계획대로 낮은 우선순위로 두고 HW(MTE·CHERI)는 장기 과제로 남긴다.

### 11.13 H2.5 마무리 — 재현 코드 없음 8건 처리

- 원천 블록을 다시 읽었다. 7건의 "`<?php` 블록 없음"은 대부분 **추출 형식 문제**였다(입력이 코드 블록 밖에 인용됨).
- **재현 입력을 원문 그대로 옮긴 3건**(`linux/corpus/repro/R*/derived.php`, `5beecbd`). 증적 `evidence/corpus-h2-20261023T232311-asanext`(`citable: true`):

| 기록 | 원문 입력 | 8.4.4 | 8.4.27 | 비고 |
|---|---|---|---|---|
| R05 bugs #74101 | block01의 unserialize 문자열 | 미재현(rc 0) | 미재현 | 2017년 수정 |
| R09 bugs #76409 | block00의 1바이트 파일(`Lw==`) + `exif_read_data(file_get_contents(...))` | 미재현 | 미재현 | 2018년 수정 |
| R16 bugs #78793 | block00의 `bug77950.tiff` 10회 루프 | 미재현 | 미재현 | 원 보고도 MSan에서만 관측(ASAN 비재현). MSan 빌드가 없어 판정 불가 |

- **스크립트가 없어 재현하지 않은 4건:** R08(SAPI rinit/rshutdown 불일치 서술만 있음), R10(FPM 크래시 보고만 있음), R22(PostgreSQL 필요, 랩 범위 밖), R56(패치 diff만 있음). R18은 기존대로 재현 코드 없음(Laravel 테스트 중 관측).
- 미재현은 안전 판정이 아니다. 수정 이전 빌드가 없어서 수정 효과를 이 랩에서 확인하지 못한다.

**H2.5 상태:** 확장 빌드(`asanext`), PHP 코드 액션(`fused`, H3에서 사용), GC 상태 오라클(G 키)은 완료했다. **payload 문법(부류를 겨냥한 입력 생성)은 하지 않았다.** H3에서 hold-out 도달 실패의 원인이 생성기라는 것이 확인됐으므로(§11.7), 이 항목은 hold-out v2 확보와 함께 다음 단계로 넘긴다(`docs/coreguard/evaluation-report.md` §5).

### 11.14 H2.5 payload 문법 → H3 재측정 (계획 §13.6 순서 정정)

§11.13은 payload 문법을 미뤄 둔 채 5단계를 완료로 표시했다. 그런데 계획 §13.4는 H2.5를 **H3 전에** 끝내야 한다고 정한다. 그래서 문법을 구현하고, 그 문법으로 H3를 다시 측정했다.

**문법**(`linux/payload-grammar.py`, `1ac52c0`, 자체 테스트 9/9):
- Phase 0 §2의 부류 정의에서 뽑은 블록을 조합한다. 블록은 잡히는 bailout 원천(컴파일 오류, SOAP WSDL 오류), 회복, GC 관찰, 소멸자가 도는 동안의 컨테이너 정리(unset, splice, `session_unset`, ArrayObject), 소멸자 동작 6종, 8.4 lazy 객체 API, 생성된 직렬화 payload(unserialize, `session_decode`)다.
- 출력은 `fused-pool.py` 형식이다. 프로그램 300개를 생성했고 문법 오류는 0/300이다.
- **지식 주의:** 블록을 설계한 사람이 hold-out의 메커니즘을 알고 있다. 이 문법으로 재발견해도 약한 증거다. hold-out을 보고 문법을 조정하지는 않았다.

**CLI 도달성**(`linux/grammar-reach.py`, 증적 `evidence/grammar-reach-20261023T232719-8.4.27-asanext`, 풀 `evidence/grammar-pool-20261023T232717-s1`):

| 결과 | 프로그램 | 블록 구성 |
|---|---|---|
| 정상 종료 + GC 보호 잔류 | 205 | SOAP만 78 / 컴파일 오류만 54 / 둘 다 73 / 둘 다 없음 **0** |
| 정상 종료 | 73 | 컴파일 오류만 8, 둘 다 없음 65 |
| PHP fatal | 22 | — |
| 메모리 오류 | **0** | 미지 시그니처 0 |

- 잘못된 WSDL로 생긴 SoapClient 오류는 **매번** GC 보호를 남긴다(78/78). 이것이 R23 패턴이다. 두 블록이 모두 없는 프로그램에서는 보호 잔류가 0이라, 다른 블록에서 오는 오탐이 없다.

**H3 재측정**(OFF, 8.4.27 `asanext` + opcache, 3시드 × 600초. 드라이버는 같은 `explore-h3.sh`이고 바뀐 것은 풀뿐이다. `POOL=`로 문법 풀(프로그램 300개)을 지정했다. §11.6 비교 대상은 php-src 융합 풀 200개다. 탐색기 코드(`--feedback off`, `fused` 액션, 본문 읽기 수정 `852770e` 포함)는 두 측정이 같다. 증적 `evidence/explore-h3-20261023T232756-8.4.27`, 3/3 rc 0):

| 풀 | 실행 | 융합 단계 | 정상 반환 | G 신호가 난 실행 | GC 보호 잔류 요청 | R46·R51 시그니처 | 미지 시그니처 |
|---|---|---|---|---|---|---|---|
| php-src 테스트 융합(§11.6) | 322 | 82 | 67 | 0/3 | 0 | 0 | 0 |
| **부류 문법** | 316 | 82 | 80 | **3/3** | 56(SOAP만 20, 서로 다른 프로그램 19) | 0 | 0 |

**해석:**
1. 생성기를 바꾸자 HTTP 수명주기 탐색이 **R23 부류(GC 보호 잔류)에 도달했다.** SOAP 진입점만으로도 20회 도달했다. §11.7의 결론("한계는 신호가 아니라 생성기")이 확인된다. 다만 위 지식 주의 때문에 이는 hold-out R23의 **독립적인 재발견이 아니다.**
2. R46(정리 중 소멸자 bailout → 이중 정리)과 R51(lazy 재진입)의 메모리 오류에는 문법이 닿지 못했다. 관련 블록은 있지만 조합 순서와 상태 조건이 맞지 않았다. hold-out을 보고 조정하면 평가가 무효가 되므로 조정하지 않는다.
3. CoreGuard 평가(§11.9·§11.11)는 이 재측정과 무관하다. CoreGuard 평가는 hold-out 재현 코드를 직접 썼다.
4. **순서 기록:** CoreGuard hold-out 평가(R23은 §11.9, R46·R51은 §11.11)는 이 문법보다 **먼저** 실행됐다. 계획 §13.6은 5(H2.5) → 6(H3) → 7(CoreGuard) 순서다.
   - 평가 결과에 미치는 영향은 없다. 사전 등록의 선정 규칙("H2.5 이후 도달 가능")이 요구하는 도달성은 사례를 CLI에서 직접 실행하는 경로다. 그 도달성은 H2 2차(`asanext` 빌드, 세 건 모두 B에서 재현)에서 이미 확인됐다. 평가 스크립트도 탐색기나 생성기를 쓰지 않는다.
   - 사전 등록 v1.1은 사례별 **1회** 평가를 정한다. 그래서 순서를 맞추려고 평가를 다시 돌리지 않는다. 다시 돌리면 hold-out을 두 번 쓰게 된다.


## 12. v2.2 순위 3 — #4 H1/H2 재분류와 영향 수치 차분 (2026-10-24, 계획 §14.3)

수정된 판정기(커밋 `c3fdd87`)를 적용해 기존 증적을 재판정했다. **PHP 재실행 없이 기록된 실행 사실(rc·ASAN·오라클·EXPECT 불일치)만으로 재분류**했다(도구: `linux/corpus/reclassify-results.py`, 증적 원본은 각 summary에 인라인 갱신).

### 12.1 H1 — closed ≠ fixed 재분류

| 항목 | 기존 | 재분류 |
|---|---|---|
| `fixed` | 33 | `closed_resolution_unverified` 32 + `fix_claimed` 1 (PR merged) |
| 나머지 유형 | open 14 / advisory 5 / 설계 3 / duplicate 1 / wontfix 1 / unmerged 1 | 변경 없음 |

- 어휘 변경: `verify-corpus.py`의 `record_type()`이 GitHub closed·bugs.php.net Closed를 더 이상 `fixed`로 표기하지 않는다. `fixed_verified`(수정 커밋+버전 관계 또는 회귀 테스트 확인)는 별도 칼럼으로 부여 예정 — 현재 0건이며, 이는 결함이 아니라 **확인 작업이 아직 없다**는 뜻이다.
- 정정 주석: `docs/historical-corpus.md` 요약 행과 findings §11 H1 기록 유형 행에 정정각.

### 12.2 H2 — 재현 결과의 outcome class 재분류 (집계, 10개 런 74+α 레코드-버전 행)

| outcome class | 건수 | 의미 |
|---|---|---|
| memory_error | 15 | ASAN/신호 — 메모리 안전 위반 관측 |
| **functional_regression** | **2** | EXPECT 불일치 — 기능 회귀이지 메모리 안전 위반이 아님(§14.2 요구 반영) |
| custom(GC 등) | 8 | 사례별 커스텀 오라클 발화 |
| completed_no_oracle | 32 | rc=0 정상 종료·오라클 미발화 — **미재현의 근거** |
| abnormal_exit_no_oracle | 25 | rc≠0 종료·오라클 미발화 — 미관측이며 미재현 근거로 쓰지 않는다 |
| no_reproducer / capability_gap / excluded_weaponized / timeout | 18/4/2/0 | 실행 전 분류 |

- **재현 집합은 불변**: 8.4.4 {R23, R41, R42, R46, R51}, 8.4.27 {R23, R46, R49, R51, R55} — 재분류는 레이블 정밀화이지 결과를 바꾸지 않는다.
- R23(양 버전)이 `functional_regression`(GC runs 정지 = 기능 오라클)으로 정정 분류됨 — findings §11에서 R23을 "8.4.27 재현"으로 세던 표현은 "기능 회귀 재현"으로 수위가 낮아진다. 메모리 오류 재현은 여전히 R46·R51(공개 미해결 경로).
- *(정정 2026-10-24, §12.5)* 수정 판정기(사실검증)로 재생성한 `reclassified.json` 집계는 **memory_error 14·custom 9** — 1행(`reproduced`+`memory_error` 오라클인데 ASAN 음성·rc∉{134,139})이 `custom`으로 강등됐다. 위 표는 0b3a020 당시 구판 분류기의 기록이다.

### 12.3 영향 수치 차분 — §10.12·§11.14·CoreGuard 평가

| 보고 항목 | 차분 |
|---|---|
| findings §10.12 (v2.1 재도출) | **변경 없음** — 재도출 판정은 `verdicts.integrity`·`differential` 기반인데 P0-A/B/C 수정은 기존 유효 실행(정상 시퀀스·프로그램 완주)에는 동일 판정을 내림. 신규 음성 픽스처(32/32)는 오분류 경로 차단이며, 기존 증적의 재판정은 순위 3 재실행(§14.3 3단계) 때 실시 — 본 절의 H2 재분류가 그 첫 적용이다. |
| findings §11.14 (H3 문법) | **해석 수위 조정** — GC 부류 3/3 "도달"은 `gc_protected` 마커 기준인데 P1-D 수정 전 실행은 rc를 기록하지 않아 (runs.jsonl에 rc 필드 없음) 마커-이후-비정상-종료 가능성을 원증적으로 배제할 수 없다. 결론(GC 부류 도달)은 유지하되 **"rc 미기록 조건" 한정**으로 수위를 낮춘다. 이후 문법 실행은 `marker_then_abnormal_exit` 분리 판정기로 재생성된 증적만 인용한다. |
| CoreGuard 평가 보고서 | **판정 어휘 갱신 필요** — `worker_contained`가 `guard_terminated_execution`으로 강등되고 `prevented` 조건이 강화됐다(CG-1). 기존 Phase 5 결과는 예방 0·감지 중심이라 수치는 불변이나, 재평가 시 `b_baseline_invalid`·`inconclusive_termination` 신규 어휘가 적용된다. 홀드아웃 1회 평가 원칙상 재실행하지 않고 어휘 매핑 주석만 부여한다. |

**유지 원칙 재확인**: 본 재분류로 §11 전체·CoreGuard observe Go/enforce No-Go/prevented=0·OFF 기저선·not_found 중 어느 것도 뒤집히지 않는다(§14.3 유지 원칙 준수). 변경은 레이블 정밀화와 미관측/미재현의 분모 분리뿐이다.

### 12.4 CG-2 — FPM 격리 매트릭스 (2026-10-24, 계획 §14.2 #3 CG-2)

결과 표·판정은 `docs/coreguard/evaluation-report.md` §6. 여기선 실행 기록과 하네스 수명주기만 남긴다(전 세션 무효 실행 사상(7디렉터리)은 계획 §14.2 CG-2 전제 (c)에 기록·삭제 완료).

- **실행**: **인용 근거 `evidence/cg2-fpm-20261024T070908`**(mc 1·4 × B/disabled/observe/enforce, faults=10 — 8셀 전부 유효: 에러 필드 0, `pool_master` 기록, `guard_events`가 observe/enforce에서 결함 수와 정확히 일치, `source_commit 9a6128e`·`citable: true`). 선행 실행 `…T055719`·스모크 `…T055632`는 미커밋 하네스 실행(`citable: false`)이라 `NON-CITABLE.md` 표지 — 판정 동일(노이즈 내, R12 재실행으로 인용성 확보). 프로토콜: 결함당 (a) fault 요청 (b) 워커 PID 집합 대조 (c) 다음 헬스, 병렬로 백그라운드 `/health` 프로버(50ms 간격, 기저선 3초 창과 폴트 창 분리), listen queue(`ss` Recv-Q) 샘플. 실행 계정 phplab.
- **하네스 결함 3건 발견·수정(당일)**:
  1. **무한 스트림 결함은 무가드 모드에서 영원히 종료하지 않는다** — per-recv 소켓 타임아웃은 청크가 계속 흐르면 만료되지 않는다(실측: FPM Recv-Q 28 적층 관측 후 중단). phase3 S1 형태(유계 512회 루프의 256회째 `unset()`이 소멸자 fatal을 본문 중간에 발화)로 재설계 — 전 모드 자가 종료 + enforce의 mid-body `_exit(70)` 보존.
  2. **포트 선점 검사가 TIME_WAIT 잔여를 점유로 오판**(`SO_REUSEADDR` 없는 bind) — 리스너 한정 검사로 수정. 거짓 양성이 fail-closed 검사를 무조건 차단해 스모크 2회 만에 검출됐다.
  3. **FPM 데몬화로 셀 정리가 비결정적** — `daemonize = no`(terminate+wait 보장) + 정리 후 포트 해제 대기·pidfile SIGKILL 폴백. root 실행 시 phplab 워커가 `cg-events.log`를 생성하지 못해 `guard_events=0`으로 오판(패치 0002의 fopen 실패→stderr 폴백) — 랩 관례대로 phplab 실행으로 해결.
- **fail-closed 기동의 실전 검증**: (2)의 거짓 양성 기간 3셀이 `port_in_use`로 차단됐다 — 전 세션 13:27 오측정(고아 스택 측정) 경로가 실제로 막히는 것을 확인.
- **evidence-sync 대소문자 충돌 버그 발견·수정**: 전체 검증에서 `lab-references-r/-R` 시드 3쌍이 사본에서 병합돼 불일치(NTFS 대소문자 무구분 — 10/23 R/r 시드 추가부터 잠복, `-r` 사본에 `-R` 내용이 들어 있었음). 동기화에 충돌 검사(fail-closed 중단)와 자기테스트 2케이스 추가, 원본 3개 `-R`을 `-R-upper`로 개명(내용 바이트 불변), 오염 사본 재복사 후 전체 검증 75,071/75,071 그린. **개명 대응표(구매니페스트 v21·v22 경로 연결용)**: `evidence/fuzz-phase5-20261022T224003/corpus/lab-references-R`·`…20261023T011018/…`·`…20261023T011329/…` → 각 디렉터리 `corpus/lab-references-R-upper`.
- **재실행(T070908)과 선행(T055719)의 수치 대비**: enforce mc=1 교체 10회(~311ms→~310ms), 폴트창 p50 263.7→262.8ms, mc=4 프로버 p99 1.4→1.9ms, 그 외 전 지표 노이즈 내 동일 — 판정 불변.
- **요약 판정**(상세는 evaluation-report §6): 재시작 증폭 음성(교체 정확히 1회/결함·listen queue 0·다음 헬스 100% 회복), enforce 비용은 요청 수준(해당 요청 reset·본문 중단)으로 한정, disabled/observe는 B와 전 지표 동치. 한계: 단일 프로버(≈20 rps)·순차 결함·`pm = static` 프로파일 한정.

### 12.5 corpus-h2 원본 복구와 재분류 재실행 (2026-10-24, 리뷰 `.zwork/handoff-20261024T1545-claude-review.md` P0·P1)

- **사고**: `0b3a020`의 구판 `reclassify-results.py`가 corpus-h2 `summary.json` 10개 **원본을 제자리 변조**(재분류 키 주입, 12:54). `95c41cd`(P1-4)는 이후 실행만 분리 출력으로 고쳤고 이미 변조된 10개는 방치됐다. 10/24 14:58 evidence-sync가 변조 바이트를 Windows 사본까지 확산시켰다.
- **2차 사고(본인)**: 복구 전에 매니페스트 v23 스냅샷을 찍어 변조 해시가 정본화됐다(10/10 불일치 확인) — v23은 폐기·삭제하고 v24로 대체한다.
- **복구**: `reclassify-results.py --restore`(신규, 커밋 `9a6128e`) — 키 제거 직렬화가 v22 사전 변조 매니페스트와 해시 일치할 때만 쓰기(fail-closed, 쓰기 후 재검증). **10/10 바이트 정확 복원**. 이어 수정 판정기로 `reclassified.json` 10개 재생성(원본 불변, 원본 SHA-256 기록).
- **판정기 재실행의 정정**: 집계 memory_error 15→14, custom 8→9 — 1행이 `reproduced`+`memory_error` 오라클인데 ASAN 음성·rc∉{134,139}라 사실검증으로 `custom` 강등(§12.2 정정각). 재현 집합 불변.
- **R12 재실행(P1)**: CG-2 매트릭스를 커밋판 하네스로 재실행해 인용성 확보(`T070908`, `citable: true`) — 구 실행 2건은 `NON-CITABLE.md` 표지 후 보존(§12.4).
- **예방(리뷰 P2·P3 수용)**: 무효 증적은 앞으로 삭제하지 않고 표지로 관리한다(이번 7디렉터리 삭제는 §14.2 (c) 기록 시점에 이미 완료된 행위). 랩 실행 계정 phplab 원칙은 §12.4에 기록.
