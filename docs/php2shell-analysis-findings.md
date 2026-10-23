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
