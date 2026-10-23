# PHP2Shell 취약점 확인·분석·E2E 테스트 계획

> 작성: 2026-10-21 21:30 KST · 대상: PHP 8.4.4 / 8.5.4 → 수정 8.4.27 · 상태: **Phase 4 실행 완료**(8.4.27 공개 후)

## 1. 배경과 현재 상태

### 1.1 첨부 보고서 요약

첨부된 「PHP2Shell 긴급 보안 취약점 기술 분석 및 패치 전 대응 보고서」는 다음을 정리한다.

- PHP 보안팀이 2026-10-21 14:00 UTC(23:00 KST) 긴급 보안 릴리스 예고, **Critical 2건(CVSS v4.0 각 9.2)**. 상세 내용·영향 버전은 릴리스 때 공개 예정.
- `PHP2Shell`은 비공식 명칭. 외부에서 CVE-2026-109618 / CVE-2026-109619 연결.
- 공개 PoC 3종 평가:
  - **PoC A (eness)**: `ext/session/session.c` 업로드 진행 상태의 `zval*` 장기 보관 → stale-pointer write → UAF → RCE 주장. 그러나 원본에 `Z_TRY_ADDREF(progress->data)`가 있어 참조 수명이 유지되며, 독립 감사(xuehuolll)는 해당 줄을 제거한 변형 빌드에서만 ASAN UAF를 재현. 주소 독립 획득도 없어 "범용 RCE"로 볼 수 없음.
  - **PoC B (0x4148)**: Docker 실험 환경. `Armed: YES`는 세션 진행 데이터 관측일 뿐 UAF 증명이 아님.
  - **PoC C (ikow)**: 세션 파일 주입·LFI·역직렬화·핸들러 불일치 등 별도 조건이 필요한 복합 경로.
- **별도 가설 (주목)**: `BG(serialize)` 요청 간 상태 재사용. 요청 파싱 중 직렬화 실행 + OOM 등 비정상 종료 → 직렬화 컨텍스트 정리 생략 → 다음 요청에서 재사용 → 특수 ASAN/계측 환경에서 UAF 보고. 일반 배포 빌드 재현 증거는 없음.
- 핵심 구분: `PS(serializer)`(세션 인코딩 핸들러 포인터)와 `BG(serialize)`(php_var_serialize 내부 상태 컨텍스트)는 다른 상태.
- 대응: `session.upload_progress.enabled=Off` 등 INI만으로는 두 CVE 전체 방어가 검증되지 않음. 패치가 우선.

### 1.2 프로젝트 현황 (2026-10-21 21:30 KST 확인)

- Windows 프로젝트 `C:\Users\user\Downloads\php`: 원본 소스 `sources/php-src-php-8.4.4/`, 랩 도구 `scripts/lab.py`, `linux/*`, `web/index.php`(/health·/session·/upload), 증적 `var/linux-evidence/`.
- WSL2 Ubuntu-24.04 `/home/phplab/php-lab`: **순정 빌드 3종** — `8.4.4-normal`, `8.4.4-asan`, `8.5.4-asan` (CLI+FPM+session, debug/ASAN, 빌드 매니페스트·바이너리 SHA 저장).
- 환경 검증 완료: 3 빌드 × {zend, system, tracked} × {buffering on, off} = **18개 조합** 정상 통과, ASAN 양성 대조(의도적 UAF) 및 GDB 소스 스택 확인, 비교 도구(compare.py) 양/음성 대조 통과.
- 감사 상태: `environment-status.json` → `ready_for_analysis_and_regression_execution`, `cve_verdict: not_run`.
- 공식 상태: php.net 공지(10-20) 확인됨. **신규 보안 릴리스는 아직 미게시** (php.net 뉴스·GitHub releases 최신 = 9월 24일자 8.4.26/8.5.11 등). → 현재는 패치 전 분석 창.

## 2. 목표

1. 첨부 보고서의 **코드 수준 주장**을 실제 PHP 8.4.4/8.5.4 원본 소스에서 정적으로 검증한다.
2. 후보 진입 경로(세션 업로드 진행, 직렬화 상태, 세션 ID 취득)에 대한 **무해한 E2E 프로브**를 ASAN 빌드에서 실행해 도달성·수명 주기·비정상 입력·비정상 종료 잔류 여부를 관측한다.
3. 결과를 증적과 함께 문서화하고 **주장별 판정표**(확인/반박/미확정)를 만든다.
4. 23:00 KST 공식 패치 공개 후 비교 분석(Phase 4)을 그대로 수행할 수 있게 준비한다.

## 3. 범위와 안전 규칙

### 3.1 범위

- 정적 분석: 8.4.4 원본 + 8.5.4 원본의 후보 파일.
- 동적 프로브: WSL 랩의 loopback(18085/19084) FPM 서버에 대한, 스스로 작성한 최소 입력만 전송.
- 판정: "코드 구조 확인", "도달성 확인", "메모리 오류 미관측" 수준. CVE 취약/안전 선언은 공식 정보 없이 하지 않는다.

### 3.2 수행하지 않는 것

- 무기화: 힙 그루밍, 해제 메모리 재점유, 함수 포인터/주소 조작, RCE 페이로드 구성.
- 공개 PoC(eness·0x4148·ikow 등) 코드의 다운로드·실행. 보고서 §17.3 및 Tenable 경고에 따름.
- 외부 대상 접근, 운영 시스템 테스트. 프로브는 전부 loopback 자기 랩 대상.
- 원본 소스 수정(빌드 무결성 유지). 프로브는 별도 디렉터리에 격리.
- ASAN 오류 관측 시: 증적 보존 → 즉시 중단·문서화. 오류를 악용으로 확장하지 않음.

## 4. Phase 1 — 정적 분석 (S1~S7)

대상 파일: `ext/session/session.c`, `ext/session/php_session.h`, `ext/standard/var.c`, `ext/standard/basic_functions.c`, `main/main.c`, `main/php_variables.c`, `main/rfc1867.c`.

| ID | 검증 내용 | 판정 기준 |
|---|---|---|
| S1 | `php_session_rfc1867_progress` 구조체가 `post_bytes_processed`/`current_file_bytes_processed`를 `zval*`로 장기 보관하는가 | file:line 인용 |
| S2 | `php_session_rfc1867_callback()`의 START/FORMDATA/FILE_DATA/END 이벤트별 동작, `zend_hash_str_find()`로 내부 포인터를 취득해 `Z_LVAL_P()` 쓰기가 실제 있는가 | file:line 인용 |
| S3 | `php_session_rfc1867_update()`의 `Z_TRY_ADDREF(progress->data)` 위치·의미, `php_session_track_init()`과의 상호작용, cancel/cleanup 경로에서 포인터 재사용 여부 | 참조 수명 추적 결론 |
| S4 | `BG(serialize)` 구조·초기화·해제 위치(요청 시작/종료), 세션 인코딩 경로가 `php_var_serialize`를 경유하는지, `PS(serializer)`와 구분 | 상태 수명 경계 확인 |
| S5 | `php_request_startup()` 내 POST 파싱(`php_hash_environment` → rfc1867)과 모듈 RINIT의 실행 순서 — 업로드 진행 콜백이 사용자 코드·세션 RINIT보다 먼저 실행되는가 | 호출 순서 확인 |
| S6 | 8.4.4 vs 8.5.4에서 위 파일들의 해당 영역 차이(plain diff) | 버전 간 변화 확인 |
| S7 | 보고서 주장 대조: 포인터 UAF 가설, `BG(serialize)` 가설, 세션 ID 폼 필드 취급(PR #22113 관련), `use_only_cookies` 우회 주장 | 주장별 확인/반박/미확정 |

산출물: `docs/php2shell-analysis-findings.md`의 정적 분석 절(파일:라인 근거 포함).

## 5. Phase 2 — E2E 프로브 (P1~P7)

하네스: `linux/probe.py` (run.py의 verify 구조 재사용 — 단일 FPM 워커, ASAN log_path, 실행 후 서버 종료, result.json). 프로브는 문서화된 PHP 기능(업로드 진행)과 정상/비정상 HTTP 입력만 사용. `session.upload_progress.min_freq=0`으로 관측 주기만 단축(편차 명시).

| ID | 프로브 | 관측 대상 | 기대/판정 |
|---|---|---|---|
| P1 | 도달성: /session으로 세션 확립 → multipart에 `PHP_SESSION_UPLOAD_PROGRESS=key` 포함, 청크 지연 전송 | 업로드 중 세션 파일에 `upload_progress_key` 키 생성, `bytes_processed` 증가 | 콜백이 사용자 코드 이전에 실행되는지 확인 |
| P2 | 수명 주기: 업로드 완료 직후 세션 파일 재관측 | cleanup=On 시 진행 키 제거, 방문 카운터 유지, 워커 PID 동일 | 정상 수명 주기 확인 |
| P3 | 중단: 파일 데이터 전송 중 연결 강제 종료 | 세션 파일 상태, 워커 생존, 다음 요청 정상 응답 | cancel 경로 확인 (buffering off에서 의미) |
| P4 | 직렬화 교차: 동일 워커에서 세션 왕복 + 진행 업로드 + 중단 반복 20회 | 방문 카운터 일관성, 워커 재사용, ASAN 무오류 | 상태 잔류 징후 탐색 |
| P5 | 경계값: 종료 boundary 누락 후 연결 종료, 중복 progress 필드(빈 값 포함), 200개 part, 4KB filename, 빈/비정상 필드명 | HTTP 응답, 워커 생존, ASAN 무오류 | 강건성 관측 |
| P6 | OOM 잔류: zend 할당기 + `memory_limit=2M` 전용 ini에서 대형 세션(직접 위조) 디코드 중 한도 초과 유도 → 동일 워커 후속 요청 관측 | E_ERROR 응답, 후속 요청 정상성, ASAN 무오류 | `BG(serialize)` 잔류 가설의 무해한 탐색(계측 패치 없는 순정 빌드 — 음성 결과도 정보) |
| P7 | 세션 ID 경로: 쿠키 없이 multipart 폼 필드 `PHPSESSID=<기존 sid>` + progress 필드 전송 | `session.use_only_cookies=On` 상태에서 해당 세션 파일에 진행 키가 쓰이는지 | ikow 우회 주장·PR #22113 현상 확인 |

실행 매트릭스(우선순위순, 각 실행은 PHPT 사전 확인 포함):

1. `8.4.4-asan` × {tracked, system, zend} × buffering off → P1~P5, P7
2. `8.4.4-asan` × {tracked, zend} × buffering on → P1, P2, P4, P5
3. `8.5.4-asan` × {tracked, zend} × buffering off → P1~P5, P7
4. P6(전용 ini): `8.4.4-asan`/`8.5.4-asan` × zend × off

산출물: `var/linux-evidence/evidence/probe-*/` (result.json, 세션 스냅샷, 로그, asan.*), 실행 요약 `docs/php2shell-analysis-findings.md`의 동적 분석 절.

## 6. Phase 3 — 통합 판정

- 정적/동적 결과를 주장별로 대조해 확인(confirmed)/반박(refuted)/미확정(unresolved) 판정표 작성.
- 근거 수준 표기(A=원본 코드 직접 확인, B=랩 관측, C=관측 못함/미확인).
- 판정 한계 명시: 특정 빌드·SAPI·설정에서의 관측은 다른 구성의 안전을 보장하지 않음.

## 7. Phase 4 — 공식 패치 공개 후 (엄격 판정)

`linux/phase4.sh <수정버전> <공식 advisory.json> [asan|normal]`

**advisory는 공식 출처만 허용한다.** `cve`(CVE-YYYY-NNNN 형식), `official_url`(php.net 또는 php-src), `affected_version`, `fixed_version`이 모두 채워져야 하고, `fixed_version`은 요청 버전과 일치해야 한다. 자리표시자 advisory는 거부되므로 **공식 매핑 없이 `regression_difference_observed`가 생성되지 않는다.**

각 단계(빌드·프로파일 5종·PoC·GDB 2모드·`http-compare` 2종·`verify-evidence`)의 종료 코드를 집계하고 `summary.json`에 기록한다. 하나라도 결과를 만들지 못하면 `inconclusive`, 하네스가 실패하면 `PHASE4_FAILED`로 종료한다. **종료 코드: 0 = 판정 완료, 2 = inconclusive, 1 = 하네스 실패.** `SKIP_BUILD=1`은 기존 빌드 매니페스트를 재사용한다.

### 7.1 실행 결과 — 8.4.4 → 8.4.27 (2026-10-21 23:15)

공식 advisory: CVE-2026-109619, affected 8.4.4 → fixed 8.4.27.

| 단계 | 8.4.4 | 8.4.27 |
|---|---|---|
| PoC (5회) | 5/5 UAF | **0/5, ASAN 없음** |
| GDB serialize 잔류 | level=1 → UAF | **잔류 0** |
| GDB unserialize 잔류 | level=1 → UAF | **잔류 0** |
| http-compare progress / oom | 기준 | `identical` / `identical` |
| 최종 | — | **`no_difference_observed` + `patch_effect_signal`** |

공식 Diff(`linux/patch-diff.sh`)는 `php_basic_early_rinit()`(요청 시작 직후 BG 상태 리셋)과 `PS(in_rfc1867_update)` + `incomplete_classes_only` 제한을 추가해, 본 계획의 S4·S5 가설과 일치한다. 상세: findings §5.

| 조건 | 판정 |
|---|---|
| 빌드 성공, 일부 테스트 실패/미실행 | `inconclusive` |
| 전후 차이 관측, 공식 매핑 없음 | `difference_observed` |
| 공식 CVE 영향·수정 버전 확인 + 차이 관측 | `regression_difference_observed` |
| 공식 패치가 원인 코드를 수정하고 오류 소멸 확인 | `patch_effect_confirmed` (수동 확인 필요) |
| 공식 수정 코드와 원인 분석까지 일치 | `root_cause_confirmed` (수동 확인 필요) |

1. php.net 보안 공지·GitHub 신규 태그로 CVE별 영향/수정 버전·공격 조건 확정. 공식 advisory JSON 작성 후 `phase4.sh`에 전달.
2. 수정 버전 순정 빌드(동일 모드) → `linux/compare.py`로 공식 회귀 PHPT 비교 (advisory.json 공식 근거 기입).
3. 본 프로브를 수정 빌드에 재실행해 전후 동작 차이 비교.
4. 공식 Diff 기반으로 S1~S6 재점검, 이 계획의 가설 순위 갱신.
5. 최종 보고서 후속판 작성(이 문서를 덮어쓰지 않고 별도 파일로).

## 8. 리스크와 완화

| 리스크 | 완화 |
|---|---|
| 프로브가 랩 외부로 영향 | loopback 바인딩만 사용, FPM/nginx는 phplab 무권한 사용자, 실행 후 자동 종료 |
| ASAN 오류를 악용으로 확장 | 정책: 관측·보존·중단 (무기화 금지) |
| 오탐(크래시 ≠ UAF ≠ CVE) | ASAN 스택·소스 라인·재현성 3요소 확인, 단정 금지 |
| 원본 소스 오염 | 원본 수정 없이 진행, audit.py 무결성 검사 유지 |
| 증적 분실 | 실행 직후 `linux-export.cmd`로 Windows `var/linux-evidence/`에 복사 |

## 9. 외부 검토 의견 반영 (2026-10-21 21:43 KST 추가)

외부 코드 리뷰(Calif.IO 연구 방법론·xuehuolll 감사·PHP 공식 Fuzzer 참조)에서 지적된 격차를 다음과 같이 반영한다.

### 9.1 반영 항목

| 검토 지적 | 반영 방식 | 시점 |
|---|---|---|
| P0: 정상 업로드 검증에 `PHP_SESSION_UPLOAD_PROGRESS` 필드가 없어 콜백 도달 증거 없음 | `linux/probe.py` P1/P2가 진행 필드를 포함한 multipart로 도달성·수명 주기를 관측. 추가로 GDB 브레이크포인트로 `php_session_rfc1867_callback` 호출 자체를 증명(P8) | 이번 턴 |
| P0: `BG(serialize).level/.data/serialize_lock` 요청 단계별 관측 불가 | `linux/gdb-probe.py` 신설: `php_request_startup` 진입·`php_var_serialize_init/destroy`·콜백에서 상태를 출력해 **정상 대조군 + OOM 잔류** 전이를 기록(P8) | 이번 턴 |
| P0: CLI/PHPT 기반 compare.py만으로는 HTTP 계층 패치 비교 불가 | `probe.py`가 HTTP E2E이므로, 공식 패치 후 **동일 프로파일·동일 입력을 수정 빌드에 재실행**하는 방식으로 전후 비교(Phase 4). 필요 시 응답·ASAN·워커 상태 3종 대조 | Phase 4 |
| Apache prefork + mod_php(prefork) 프로파일 부재 | **구축·실행 완료**: `linux/build-apache.sh`(apxs2·ASAN), `linux/apache-lab.sh`(httpd -X, loopback 18088), `linux/apache-poc-matrix.sh`. A/B 재현 3/3, 동일 ASAN 스택 | 이번 턴 |
| P1: INI 조합 부족(직렬화 핸들러·메모리 한도·기능 On/Off) | `probe.py` 프로파일에 `oom`(php 핸들러)·`oomps`(`php_serialize` 핸들러)·`lax`(strict Off) 추가. `session.upload_progress.enabled=Off` 대조는 Phase 4 매트릭스로 | 이번 턴 + Phase 4 |
| P1: 증적 재검증성(해시·요약) | `linux-export` 후 `var/linux-evidence/evidence-manifest.sha256` 생성(모든 증적 파일 SHA-256). 실행 요약은 findings 문서에 기록 | 이번 턴 |
| Calif 정적 분석 방법론(`php-unserialize-audit`) | `Serializable::unserialize()` 재진입·`__wakeup/__destruct` 상태 변경·`var_hash` 수명·세션 디코더 차이를 정적 체크리스트로 추가(S9). 자동 스캔 결과는 취약점 확정이 아니라 가설로만 취급 | Phase 4 |
| PHP 공식 Fuzzer(`sapi/fuzzer`, `php-fuzz-unserialize`) | `--enable-fuzzer --enable-pic` 별도 빌드 + 기존 Corpus 통합을 Phase 4 후속으로 계획. 신규 퍼저 개발은 하지 않음 | Phase 4 이후 |

### 9.2 판정 기준 (검토 의견 §6 수용)

| 관측 결과 | 허용 판정 |
|---|---|
| HTTP 200 + 세션 진행 상태 갱신 | 해당 코드 경로 **도달** |
| HTTP 500/502, 워커 재시작 | 비정상 동작 관측, **원인 미확정** |
| ASAN에서 동일 주소 해제 후 접근 | 해당 빌드·조건에서 **메모리 오류 재현** |
| 수정되지 않은 정식 PHP에서 반복 재현 | 취약점 가능성 **강하게 뒷받침** |
| 패치 전 재현·후 소멸 | 패치 관련 **회귀 차이** |
| 공식 코드 변경·공지와 원인 일치 | 해당 CVE **근본 원인 확정 가능** |

`Armed: YES`, 502, 워커 재시작만으로 UAF를 확정하지 않는다. 8.4.4 미재현만으로 8.4 전체 안전을 선언하지 않는다.

### 9.3 E2E의 정의와 명시적 비목표 (2026-10-21 22:10 추가)

**E2E 검증의 정의(이 프로젝트):** 하나의 입력이 ① HTTP 계층을 통과해 ② PHP 내부의 특정 C 함수·콜백에 도달하고 ③ 내부 상태(zval·HashTable·직렬화 컨텍스트)를 변화시키며 ④ 관측 가능한 오류 증거(ASAN/UBSan/크래시/로그)를 남기고 ⑤ 그 결과가 판정 어휘로 기록되는 것까지, **입력→경로→상태→증거→판정** 전 구간을 실제 실행으로 연결하는 것.

**명시적 비목표(수행하지 않음):**

| 항목 | 이유 |
|---|---|
| 무기화된 익스플로잇 작성(힙 그루밍, 해제 메모리 재점유, 함수 포인터·주소 조작, RCE 페이로드) | 취약점 검증과 공격 도구 제작의 경계. 산출물이 특정 랩이 아니라 동일 버전 PHP 서버 전반에 쓸 수 있는 범용 공격 도구가 됨 |
| 공개 PoC/익스플로잇 코드 다운로드·실행 | 보고서 §17.3, Tenable 경고 |
| 운영·외부 시스템 대상 시험 | 격리 원칙 |

**대신 제공하는 영향 평가(합법 범위):** ① 트리거 재현성·반복성 측정(동일 입력 N회), ② 영향 등급 분류(요청 실패·워커 종료·프로세스 크래시), ③ 조건 의존성 지도(SAPI·버전·할당기·INI), ④ 패치 전후 회귀 비교, ⑤ 탐지·완화 규칙 검증. “이 결함이 운영에서 무엇을 일으키는가”에 답하면서 코드 실행 능력은 만들지 않는다.

### 9.4 외부 연구 방법론 통합 (첨부 요청 §3·§5 반영)

| 연구/도구 | 적용 방법론 | 구현 파일 | 실행 검증 | 미구현 |
|---|---|---|---|---|
| FlowFusion (USENIX'25) | PHPT 입력 활용, 설정 변형, 메모리 오류 수집, 실패 입력 보존·축소 | `linux/fuzz-smoke.sh`(공식 fuzzer 스모크) | **부분 검증** — 485,434회, crash 0 | 데이터흐름 변형·자동 축소 |
| PHP 공식 Fuzzer SAPI | `--enable-fuzzer` 빌드, 기존 Corpus | `linux/build-fuzzer.sh`, `linux/fuzz-smoke.sh` | **실행 검증** (60s, 19 seeds) | 사전(dict) 생성 이슈 |
| Calif MAD Bugs / php-unserialize-audit | `Serializable` 재진입, `__wakeup/__destruct`, `var_hash` 수명, 세션 디코더 차이 | 정적 체크리스트(S9, 문서) | 문서만 | 자동 스캔 |
| ZendDiff | 내부 상태 프로빙·차등 비교, 비결정성 제거 | `linux/gdb-probe.py`, `linux/http-compare.py`, `linux/jit-compare.sh` | **부분 검증** — 출력 수준 3모드 동일 | 내부 상태 프로빙(JIT) |
| ATROPOS / PHUZZ | 상태 유지 HTTP 시퀀스, 스냅샷·복원, 오류 수집 | `linux/probe.py` P4(교차 요청) | **실행 검증** | 커버리지 계측 |
| WAFFLED | 원문 바이트 보존, WAF vs PHP 파싱 비교, 오탐/누락 평가 | `linux/waf-lab.sh`, `linux/waf-compare.py` | **실행 검증** (10변형, 2건 누락) | CRS/상용 WAF |
| FUGIO / FUSE | 애플리케이션 의존 조건 분리, 확장 지점 | 설계 문서(§3.1) | — | 낮은 우선순위 |
| Check Point unserialize | `zval`/`HashTable` 소유권, 참조 카운트, 재진입 | findings §1(S3·S4) | **정적 검증** | — |

### 9.5 판정 상태 어휘 (첨부 §5.5 수용)

`result.json`의 `status`/`verdict`는 다음 어휘로 통일한다.

| 상태 | 의미 | 현재 적용 예 |
|---|---|---|
| `environment_ready` | 빌드·서버·사전 점검 통과 | 기존 matrix 18조합 |
| `code_path_reached` | 콜백/함수 도달 증거(GDB·세션 데이터) | P1/P2, P8 이벤트 0~5 |
| `memory_error_observed` | ASAN/UBSan이 할당·해제·사용 스택과 함께 보고 | P8 (var.c:732) |
| `crash_observed` | 워커/프로세스 비정상 종료(SIGSEGV·SIGABRT), 원인 미확정 | zend 할당기 P8 SIGSEGV |
| `request_aborted_worker_exit` | 요청 단위 실패 후 워커 종료(예: FPM exit 70) | oom 프로파일 4조합 |
| `regression_difference_observed` | 동일 입력에서 전후 빌드 차이 | `http-compare.py` 검증 |
| `root_cause_confirmed` | 공식 패치·공지와 원인 일치 | 미도달(패치 전) |
| `inconclusive` / `not_run` | 증거 부족 / 미실행 | 패치 비교, Apache |

### 9.6 PoC 트랙 (2026-10-21 22:12 추가, 22:35 증거 연결 정정)

> 시각 정정: 이전 판의 `23:10`은 오기이며 실제 추가 시각은 22:12 KST다(증적 타임스탬프·커밋 시각 기준).

**PoC의 정의와 계층** — “증명”을 한 덩어리로 보지 않고 4단계로 나눈다.

| 단계 | 내용 | 상태 | 증거 |
|---|---|---|---|
| L0 트리거 PoC | 입력 시퀀스가 취약 경로를 지나 메모리 오류를 재현 | **완료** | `poc-bgserialize.py`: 5/5, ASAN `heap-use-after-free` (var.c:732) |
| L1 재현율 | 동일 조건 반복 시 재현되는 비율 | **완료 (100%)** | `var/linux-evidence/evidence/poc-*/result.json` (reproduced 5/5) |
| L2 영향 등급 | 요청 실패·워커 종료·프로세스 크래시로 분류 | **완료** | A=500, B=연결 종료(프로세스 abort), FPM은 exit 70 |
| L3 익스플로잇 | 제어된 코드 실행 체인 | **수행 안 함(정책)** | 계획 §9.3 비목표 |

**L0 PoC의 최소 조건 (재현에 필요한 것):**

1. CLI 내장 서버(요청 실패 후에도 프로세스 유지) + ASAN + `USE_TRACKED_ALLOC=1`.
2. `memory_limit=8M`과 3MB 위조 세션(세션 저장 경로에 대한 로컬 쓰기 필요 — 원격 단독 PoC 아님).
3. 요청 A: multipart에 `PHPSESSID`(위조 세션) + `PHP_SESSION_UPLOAD_PROGRESS` + 파일 → 파싱 중 재인코딩이 한도 초과로 bailout.
4. **A와 B 사이에 다른 HTTP 요청이 없어야 함** — 어떤 요청이든 `zend_activate_modules`에 도달하면 `PHP_RINIT_FUNCTION(basic)`이 `BG(serialize)`를 memset해 잔류를 지운다(이번에 실측으로 확인).
5. 요청 B: 같은 프로세스에서 진행 업로드 → 파싱 중 encode가 잔류 컨텍스트를 재사용.

**도구:** `linux/poc-bgserialize.py` (`--iterations N`, 기본 5). 각 회차는 새 프로세스로 시작하며, 요청 A/B 상태·OOM 로그·ASAN 요약·첫 프레임을 `result.json`에 기록한다.

### 9.7 판정 정확도와 자동 검증 (외부 검토 반영)

| 항목 | 도구/규칙 | 상태 |
|---|---|---|
| 회차별 ASAN 증거 연결 | `poc-bgserialize.py` — 회차 시작 전 스냅샷 제외, 신규 보고서만 채택, PID 일치 | 적용·검증 |
| GDB 판정 인덱스 | `gdb-probe.py` — 전이 기반 OOM 요청 식별(고정 인덱스 제거) | 적용·검증 |
| 매트릭스 종료 코드 | `probe-matrix.sh` — `pipefail` + `PIPESTATUS` 집계 | 적용 |
| HTTP 비교 판정 분리 | `http-compare.py` — `--advisory` 없으면 `difference_observed`만 | 적용·검증 |
| 증적 자동 감사 | `verify-evidence.py` — PoC 회차/PID, GDB 인덱스, 매니페스트 해시·BOM | **passed** |
| 원본 증적 보관 | `docs/evidence-manifest-20261021.sha256`(1044개) — 저장소에는 해시만, 원본은 `var/linux-evidence/` | 적용 |

### 9.8 외부 연구 대조 반영 (2026-10-21 22:55 추가)

| 외부 지적 | 우리 상태 | 처리 |
|---|---|---|
| Bug S — `BG(serialize)` 요청 간 UAF | 재현 완료(CLI 5/5, Apache 3/3+2/2) | 유지 |
| **Bug U — `BG(unserialize)` 요청 간 UAF** | **미검증 → 재현 완료** | `linux/gdb-unserialize.py` 신설: decode 단계 OOM(5M 한도) → 잔류 level=1 → 다음 요청 decode 재사용 → ASAN `tmp_var`(var_unserializer.re:166) |
| Apache prefork + mod_php | 완료(3/3+2/2, 프로세스 유지 확인) | §4.6 |
| PoC 재현율 판정기 결함 | 수정 완료(회차별 신규 보고서·PID 일치) | `verify-evidence.py` |
| 19h “부품 수 제한 시 END 생략” | **반박** — 코드상 `goto fileupload_done`이 END를 실행(rfc1867.c:795-797→1267-1272), 동적 대조(P11)에서도 cleanup 실행 | `probe.py --profile parts`: `key_removed=true` |
| HTTP 입력만으로 OOM(Arm 단계) | **측정 완료(음성)** — 901필드×4KB에서 OOM 없음 | `probe.py --profile arm` |
| `cleanup=Off`에서 진행 키 잔류 | **확인** — 완료 후에도 키·done 유지 | `probe.py --profile cleanup` |
| Zend vs 계측 할당기 구분 | 부분 완료 | zend 모드에서 decode OOM로 다른 지점임을 확인(§2.7c) |

### 9.9 P0/P1 잔여 항목 진행 상태 (2026-10-22 00:05)

| 항목 | 상태 | 근거 |
|---|---|---|
| 8.5.12 교차 검증 | **완료** | PoC 0/5, ASAN 0, identical (findings §6.1) |
| CVE-2026-109618 고유 경로 | **부분** — 조건·처리 차이 재현, 손상 미재현 | `probe.py --profile oomparse` (findings §6.2) |
| 109619 다른 변형 | **정적 조사 완료** — 시작 단계 (un)serialize는 session.c가 유일, url_scanner/fatal backtrace는 별도 상태류 | `linux/serialize-sites.sh` (findings §6.3) |
| 탐지 룰 | **구축·부분 검증** — ModSecurity 6/10(우회 2건 유지, 통제 아님), Sigma 4종(구조 검증) | `linux/detect-rules/`, `linux/validate-rules.py` (findings §6.4·§6.5) |
| Phase 4 PoC 판정 | **완료** — `poc_valid`(결과 JSON·5회·회차별 result)를 harness 조건에 포함 | findings §6.6 |
| Phase 4 증적 귀속 | **완료** — `verify-evidence --since/--root`로 이번 실행 증적만 인정 | 음성 대조 exit 2 |
| Sigma 운영 호환 | **부분** — `.php` 경로 필터 제거, SIEM 변환·실행은 미검증 | validate-rules 구조 PASS |
| ModSecurity 예제 표기 | **완료** — `*.example.conf`, “운영 적용 금지” 헤더 | waf-compare 6/10 유지 |

### 9.14 Calif 연구 대조 반영 (2026-10-22)

원문: [A Tale of Two PHP Remote Vulnerabilities](https://calif.io/php2shell/) (Calif·OpenAI·Wiz, 2026-08 발견 → 10월 릴리스).

#### (1) 3경로 분류와 우리 커버리지

| 경로 | 원인 | SAPI | 우리 상태 |
|---|---|---|---|
| A. 부분 초기화 HashTable (109618) | `_zend_hash_str_add_or_update_i`가 count를 먼저 올리고 key 할당에서 fatal → teardown이 미초기화 Bucket 소비 | mod_php (≥7.3) | **미재현** (P14는 FPM) |
| B. Session 전역 상태 (109619) | 파싱 중 `PS(id)`·`PS(http_session_vars)`가 요청 힙을 가리킴 → fatal로 END/RSHUTDOWN 생략 → 워커 생존 → 다음 요청 END cleanup이 소비 | mod_php (≥5.4) | **미검증** |
| C. `BG(unserialize)` post-RINIT (109619) | RINIT 이후 앱 실행 중 unserialize fatal → 워커 생존(FPM·mod_php 공통, 앱 의존 — §9.14-5 정정) → 다음 요청 재사용 | PHP-FPM·mod_php (앱 의존) | **부분** (pre-RINIT만 재현; FPM이 자체 미커버 SAPI라 P17 대상) |

#### (2) OOM 전달 기법 (Calif) vs 우리 실험

| 기법 | 원리 | 우리 시험 |
|---|---|---|
| post_max_size vs 실제 소비 불일치 | `Content-Length`만 검사, chunked/lengthless·압축 해제로 실제 바이트 초과 | **미시험** |
| `filename=""` 빈 업로드 + 중첩 필드명 | `$_FILES` 6항목 × 중첩 HashTable/Bucket/키 할당 → 본문 8MiB 미만으로 128MiB 소진 | **미시험** (P14는 일반 필드 30k) |
| 일반 필드 다수 | 파서 배열 오버헤드 | 시험(8.4.4 OOM/8.4.27 조기 종료) |

#### (3) 신규 실험 설계 — **실행 완료(2026-10-22, 결과는 §(6)·findings §8)**

| ID | 목표 | 설계 | 판정 기준 |
|---|---|---|---|
| **P15** | 109618 Path A 재현 | Apache mod_php(ASAN/tracked) + `filename=””` 중첩 업로드로 key 할당 OOM 유도 — memory_limit×부품 수×중첩 깊이 스윕으로 fatal 지점 조준. 8.4.4 vs 8.4.27 | ① 백트레이스로 fatal 사이트가 key 할당(`zend_hash.c:958`, 8.4.4 기준)임을 확인(resize `:952`와 구분) ② ASAN Bucket 소비 보고 **또는** GDB 미초기화 bucket 소비 관찰 시 “재현” (§9.14-5a) |
| **P16** | 109619 Path B(PS 상태) | mod_php: 요청 A(파일 파트+progress → early session init 후 파싱 fatal)는 findings §4.6 Apache Bug S 재현과 동일 형상 재사용, 요청 B(파일 파트 없는 progress + 폼 필드 `PHPSESSID`)만 신규. GDB로 `PS(id)`/`PS(http_session_vars)`·`PG(modules_activated)` 관측. 8.4.4 vs 8.4.27 | PS가 해제 힙을 가리키며 소비되면 “재현” (§9.14-5b) |
| **P17** | 109619 Path C(post-RINIT, FPM) | 랩 전용 엔드포인트에서 unserialize 도중 OOM fatal(런타임 fatal → 정상 shutdown 후 워커 생존 기대) → 다음 요청(파싱 중 decode, `gdb-unserialize.py` 소비자와 동일 형상)에서 `BG(unserialize)` 재사용 관측. `pm.max_children=1`·A/B 사이 타 요청 금지. 8.4.4 vs 8.4.27 | 워커 동일 PID + 다음 요청 ASAN UAF (§9.14-5c) |
| **P18** | OOM 전달 matrix | chunked/lengthless, 압축 해제 필터, 빈 업로드 중첩 각각의 OOM 도달 여부 + **배포 가능 조합** 표기(mod_php=prefork↔HTTP/2 충돌, FPM은 프록시 `CONTENT_LENGTH` 합성 의존). 빈 업로드 증폭 arm은 P15와 통합 실행 | 본문/힙 비율, 도달 지점, 실배포 성립 여부 기록 (§9.14-5e) |

**안전 경계:** P15~P17도 **메모리 오류 관측까지**이며 RCE 체인 작성·실행은 계속 비목표다.

#### (4) 문서 정정 반영

- 109618/109619 매핑 정정(§5.1), FPM 문구에 “이 시퀀스에서는” 한정(§2.7, §3.2, §4.6), P12/P14 음성 결과에 전달 형태·SAPI 한정(§4.9a, §6.2).
- findings §7에 Calif 대조·커버리지 표·문구 정정 기록.

#### (5) 재검토 보강 (2026-10-22, 원문·공식 advisory·8.4.4 소스 대조)

P15~P18 설계에 대한 재검토 결과다. 상세 근거는 findings §7.5.

**a. P15 — fatal 지점 조준과 판정 이중화.** 8.4.4 `Zend/zend_hash.c:955-956`(`nNumUsed++`·`nNumOfElements++`)가 `:958`(key `zend_string_init`)보다 먼저 실행되는 것이 Path A의 전제다. 단 `:952`의 `ZEND_HASH_IF_FULL_DO_RESIZE`(realloc) 실패는 bucket을 남기지 않는 **다른 지점**이므로:

- **조준:** memory_limit × 빈 업로드 부품 수 × 중첩 깊이를 스윍해 fatal이 key 할당에 착지하는 매개변수를 탐색. resize·값 문자열 등 인접 할당에 걸리면 조정.
- **판정:** ① 백트레이스로 fatal 사이트가 key 할당임을 확인(P14 "일반 파싱 OOM"과의 차별화 근거). ② "재현" = ASAN Bucket 소비 보고 **또는** GDB로 `zend_hash_destroy`가 `nNumUsed`까지 순회하며 미초기화 bucket을 소비하는 관찰. stale bucket이 우연히 유효·미포이즌 메모리를 가리키면 ASAN이 침묵할 수 있어 음성을 부정 증거로 쓰지 않는다("이 조건에서 미재현"으로 한정).
- **8.4.27 해석:** 소멸 형태가 전달 차단형(fatal 자체 미발생, P14의 8.4.27 결과 방식)인지 소비 지점 제거형인지 구분해 기록 → `root_cause_confirmed`(109618) 승격 근거를 깨끗하게 유지.

**b. P16 — 생산자 재사용·GDB 체크리스트·8.4.27 대조.** 요청 A(생산자)는 findings §4.6 Apache Bug S 재현과 동일 요청 형상을 그대로 쓰고 요청 B(소비자)만 신규 구현한다. GDB 관측에 `PS(id)`·`PS(http_session_vars)` 외에 ① `PG(modules_activated)=0` 게이트(모듈 RSHUTDOWN 생략 원인), ② Session RSHUTDOWN 실제 스킵, ③ 요청 B의 END cleanup이 댕글링 PS를 소비하는 지점을 추가한다. 요청 B의 SID는 폼 필드 `PHPSESSID`로 전달(S7/P7에서 재현). 8.4.27 대조 포함.

**c. P17 — 소비자 형상·타이밍 제약·8.4.27 대조.** 소비자 재사용 지점은 파싱 중 decode 경로(업로드 진행)로 `gdb-unserialize.py`의 소비자와 동일 형상임을 명시한다(원문 Path C도 소비자는 파싱 중 세션 시작 경로). 타이밍 제약 "A/B 사이 타 요청 금지"(findings §4.5 학습 — basic RINIT의 memset이 잔류를 지움)가 FPM에도 동일 적용되므로 `pm.max_children=1` + 순차 요청을 조건으로 명시. 요청 A는 런타임 fatal이므로 정상 shutdown 후 워커 생존(500 응답 + PID 동일)이 기대값이다. 8.4.27 대조: 생산자(앱 OOM fatal)는 그대로 발생해도 `php_basic_early_rinit()` 재설정으로 재사용 소멸 예상 — 잔류 생존과 소비 차단이 분리된 patch_effect 시험이 된다.

**d. 8.4.27 대조 공통화.** 기존 P15에만 있던 수정 빌드 비교를 P16/P17에도 추가해 3실험 공통으로 만든다(Phase 4 판정 방법론 — 재현→수정 빌드 소멸→`patch_effect` — 과 정합). 예상 소멸 형태: P16은 P15와 마찬가지로 전달 차단형 가능, P17은 생산자 잔존 + 재사용 소멸형.

**e. P18 — 배포 가능 조합 표기.** 결과가 위험 평가로 연결되도록 각 arm에 "실제 배포에서 성립하는 조합인가"를 기록한다. mod_php는 prefork 강제·HTTP/2는 event/worker 필요 → "lengthless HTTP/2 + mod_php"는 실배포 불가 조합. FPM은 앞단(nginx/Apache)이 dechunk 후 `CONTENT_LENGTH`를 합성하는 구성이 많아 chunked 불일치 arm은 프록시 구성 의존으로 기록. 압축 해제 mismatch는 Apache 입력 필터로 랩 재현 가능 arm. 빈 업로드 증폭 arm은 P15의 전제 기법이므로 P15와 통합 실행.

**f. 우선순위 참고.** CVE 커버리지 기준(109618이 유일한 미재현 CVE이므로 P15 우선)은 유지하되, 비용·확정 속도 기준으로는 P16(생산자 이미 확보, 소비자만 신규)을 먼저 확정하고 P15 조준 스윕을 병행하는 순서도 합리적이다. → 실제 실행은 P16 → P15 → P17 → P18 순으로 진행했다.

#### (6) 실행 결과 (2026-10-22, 상세는 findings §8)

| ID | 8.4.4 | 8.4.27 (소멸 형태) | 핵심 증거 |
|---|---|---|---|
| **P16** Path B | **재현 3/3** (ASAN UAF `ps_files_close` + 3종 스택) | 소멸 0/3 — MULTIPART_EVENT_START `php_rinit_session_globals()` 선행 리셋(소비 지점 리셋형) | GDB ①`modules_activated=0` ②RSHUTDOWN 스킵 ③요청 B가 요청 A와 동일 `PS(id)` 포인터·sid 사용 |
| **P15** Path A | **재현 3/3** (fatal 328B 키 할당 → `zend_array_destroy` SEGV) | 소멸 — 400·fatal 없음(`ZEND_HAS_OOM` 조기 종료, 전달 차단형) | GDB fatal 사이트 = `_zend_hash_str_add_or_update_i` **zend_hash.c:958**(nNumUsed++ 이후). 28M 대조(new_array 착지)는 크래시 없음 — 인과 입증 |
| **P17** Path C | **재현 3/3** (FPM 워커 생존 → 요청 B `tmp_var` UAF) | 소멸 0/3 — `php_basic_early_rinit()` BG 리셋(생산자 잔존+소비 차단형) | 3종 스택: 할당 `zif_unserialize`(앱 실행 중) / 해제 요청 A 종료 / 사용 요청 B 파싱 중 decode |
| **P18** 매트릭스 | mod_php+chunked **우회 실증**(경고 없이 실제 5.77MB 도달·fatal); nginx(버퍼링 on)은 413로 중화; gzip arm은 이 랩 구성에서 미성립; 빈 업로드 증폭 2.56MB→32MB+ | — | `oom-delivery-*` 증적 |

**판정 갱신:** `root_cause_confirmed`(CVE-2026-109618) 성립(랩 조건 한정). 109619는 세 경로 모두 재현. 안전 경계(관측까지, RCE 비목표)는 전 실험에서 유지됐다.

## 10. 산출물 목록

1. `docs/php2shell-analysis-plan.md` — 이 문서.
2. `linux/probe.py` (+ `linux-probe.cmd`) — HTTP E2E 프로브 하네스(P1~P7).
3. `linux/gdb-probe.py` (+ `linux-gdb.cmd`) — 요청 수명·직렬화 상태 계측 하네스(P8).
4. `linux/http-compare.py` — 동일 입력 HTTP 전후 비교 도구(판정 어휘 포함).
5. `linux/poc-bgserialize.py` — L0 트리거 PoC 러너(재현율 측정, 익스플로잇 아님).
6. `linux/build-apache.sh`, `linux/apache-lab.sh`, `linux/apache-poc-matrix.sh` — Apache mod_php 랩(빌드·기동·재현율).
7. `linux/verify-evidence.py` — 증적 자동 감사(회차별 ASAN·PID, GDB 인덱스, 매니페스트).
8. `linux/gdb-unserialize.py` — `BG(unserialize)`(Bug U) 상태 계측·재현 하네스.
9. `linux/waf-lab.sh`, `linux/waf-compare.py` — ModSecurity vs PHP 파싱 대조 랩.
10. `linux/build-fuzzer.sh`, `linux/fuzz-smoke.sh` — 공식 fuzzing SAPI 빌드·스모크。
11. `linux/build-jit.sh`, `linux/jit-compare.sh` — opcache/JIT 차등 비교.
12. `linux/patch-diff.sh` — 수정 릴리스 Diff 수집(원인 일치 확인).
13. `linux/detect-rules/` — ModSecurity·Sigma 탐지 룰과 검증 기록.
14. `linux/validate-rules.py` — 룰 구조 검증(UUID·AND/OR·condition 참조).
15. `linux/serialize-sites.sh` — 시작 단계 (un)serialize 호출지 정적 조사.
5. `var/linux-evidence/evidence/probe-*/`, `probe-gdb-*/` — 프로브 실행 증적.
6. `var/linux-evidence/evidence-manifest.sha256` — 증적 해시 매니페스트.
7. `docs/php2shell-analysis-findings.md` — 정적·동적 분석 결과 및 주장별 판정표.

## 11. Phase 5 — 신규 경로 탐색 계획 (2026-10-23, 미실시)

> 두 기준을 동시에 목표로 한다. **기준 1(유계)**: 패치가 덮지 않은 같은 부류의 잔존 위험 확인 — 열거 가능 공간, "충분" 판정 가능. **기준 2(무계)**: 미지 부류 탐색 자동화 — 완전성 보장 없음, 음성은 "못 찾음"으로만 기록.

### 11.1 목표와 충족 정의

| 기준 | 목표 | "충족"의 정의 (완료 판정) |
|---|---|---|
| 1. 잔존 위험 확인 | 8.4.27/8.5.12 패치가 보호하지 않는 ① stale-state 부류(생략된 정리로 잔류하는 요청 소유 상태) ② count-before-init 부류(증가 후 낙할 수 있는 할당 → 부분 초기화) 후보의 열거·판정 | 후보 열거 완료 + 우선순위 상위 5개의 동적 판정(재현/이 조건에서 미재현/도달 불가) + 전 후보의 정적 판정 기록 |
| 2. 미지 부류 탐색 | 가설 없이 오류를 만들어내는 탐색 파이프라인(퍼징·상태 잔류 diff) 구축·가동 | 파이프라인 가동 + 야간 3회 이상 실행 + 발견물 전건의 부류 분류 완료. **"신규 경로 발견" 자체는 충족 조건이 아님** |

> **2026-10-23 정정(이슈 #1 반영):** 당초 기준 문구는 "야간 3회 이상"이었으나 실제 수행은 **25분×3회**(세션 내 실행 가능 규모, findings §9.4)였다. 기준을 실제 수행과 일치하는 표기로 정정하며, 야간 8h급 지속 실행은 `linux/fuzz-phase5.sh`로 남은 과제로 둔다. 또한 `php-fuzz-unserialize`는 HTTP multipart 파싱·요청 간 상태 수명을 직접 커버하지 않는다(커버리지 한계, §12.2).

### 11.2 공통 규칙

- **안전 경계 유지**: 메모리 오류 관측까지만. 힙 그루밍·주소 조작·RCE 체인·운영/외부 시험은 계속 비목표.
- **판정 어휘(신규 경로용)**: 공식 advisory가 없으므로 `candidate_identified`(정적) / `memory_error_observed_new_path`(동적, ASAN+재현성) / `already_patched`(A1 보호 목록과 일치) / `not_reachable` / `not_found(못 찾음)`. CVE 매핑·`root_cause_confirmed`는 공식 확인 전 불가.
- **발견 시 처리 (D1)**: 관측 즉시 중단 → 증적 보존·재현 조건 기록 → **php.net 보안 채널(security@php.net) 책임 신고**(크래시 리포트·재현 스크립트 첨부, 익스플로잇 미포함) → 신고 확인 전 본 저장소의 해당 상세 비공개 전환 검토 → 업스트림 수정 공개 후 Phase 4 사다리로 소멸 확인.
- **중단 기준**: Stage A 후보 소진 + Stage B 상위 5개 판정 + Stage C 야간 3회 음성, 또는 총 1주 경과 중 먼저 도래하는 지점. 연장은 별도 승인.

### 11.3 Stage A — 정적 열거 (기준 1, 유계)

| ID | 작업 | 방법 | 산출 |
|---|---|---|---|
| A1 | **패치 보호 목록 역추출** | 8.4.27 Diff에서 early-reset/가드 추가 지점 전수 목록화(`php_basic_early_rinit`, `php_url_scanner_early_rinit`, MULTIPART_EVENT_START의 `php_rinit_session_globals`, `ZEND_HAS_OOM` 각 삽입점, `memory_hard_limit_percent`, `in_rfc1867_update`) | "보호된 상태/지점 ↔ 막는 경로 유형" 표 — 이후 모든 후보의 `already_patched` 판정 기준 |
| A2 | **동형 stale-state 스캔** (+ 기존 S9 흡수) | ① 모듈 전역(BG()·기타 ZEND_MODULE_GLOBALS) 중 "RINIT 전·파싱 중 초기화 가능 + fatal 시 정리 생략 가능 + 다음 요청이 소비 가능" 조건 스캔(`linux/state-sites.sh` — `serialize-sites.sh` 확장). ② S9 체크리스트 실행: Serializable::unserialize 재진입, `__wakeup/__destruct` 상태 변경, `var_hash` 수명, 세션 디코더 차이 (Calif php-unserialize-audit 방법론, 결과는 가설로만) | 후보 상태 목록(전역명 × 수명 경계 file:line × 예상 소비자 × SAPI) |
| A3 | **count-before-init 패턴 스캔** | "카운터/길이/인덱스 증가 → 낙할 수 있는 할당(emalloc 계열·`zend_string_init`·realloc)" 순서가 부분 상태를 노출하는 구조 스캔. 시작점: `zend_hash.c` 유사 패턴 외 `smart_str`·`zend_llist`·버킷/슬롯 배열류. 각 지점에 `ZEND_HAS_OOM` 가드 유무 병기 | 후보 지점 목록(file:line × 증가문 × 낙할 수 있는 할당 × 가드 유무) |
| A4 | **버전 스코프 확정** | 기본: 8.4.27·8.5.12 소스(+ 필요 시 8.3.36·8.2.35 태그 소스만). master(8.6-dev)는 정적 스캔에만 포함. 빌드 추가는 후보 발굴 시 | 스코프 결정 기록 |

**우선순위 산식**: 도달성(원격 입력 경로) × 잔류 가능성(정리 생략 조건) × 소비 가능성(pre-RINIT/재사용 경로) × 미보호(A1 비일치).

### 11.4 Stage B — 동적 검증 (기준 1, 상위 5개)

| ID | 후보 유형 | 하네스 | 판정 |
|---|---|---|---|
| B1 | stale-state 후보 | `gdb-pathb.py` 템플릿 복제 — 대상 전역 포인터 브레이크포인트 + 생산자 2종(파싱 중 fatal / 앱 런타임 fatal, `/unserialize` 패턴) × 소비자 2종(pre-RINIT 파싱 / 앱 코드) | ASAN 3종 스택 또는 GDB 잔류·재사용 관측 시 `memory_error_observed_new_path`. ASAN 음성은 "이 조건에서 미재현"(§9.14-5a 이중 판정 유지) |
| B2 | count-before-init 후보 | `poc-patha.py` 조준 스윕 재사용 — 해당 할당에 fatal 착지(사이트 백트레이스 확인) → teardown 소비 관측 | fatal 사이트 확인 + teardown 소비 시 재현. 카운터 이전 착지 대조군 포함 |

각 후보에 8.4.27(또는 해당 수정 버전) 소멸 확인 병행 — 소멸되면 잔존 아님.

### 11.5 Stage C — 탐색 자동화 (기준 2, 무계)

| ID | 작업 | 내용 | 비고 |
|---|---|---|---|
| C1 | **퍼저 파이프라인** | 공식 `php-fuzz-unserialize` + Corpus 통합(공식 seed + 자체 직렬화 코퍼스: 위조 세션·progress 페이로드) + **사전 생성 이슈 해결**(`generate_unserialize_dict.php`를 session/standard 포함 빌드에서 재생성) + 장기 실행(야간 8h) + 축소 스크립트 | 발견물은 A1/A2 부류 분류 → 알려진 부류면 회귀 기록, 미지면 D1 절차. multipart/rfc1867 직접 퍼저 타깃은 공식 SAPI에 부재 시 **신규 개발 = 승인제**(기존 비목표 경위) |
| C2 | **상태 잔류 diff 자동화** | `linux/gdb-state-diff.py` — 등록된 전역 상태(레벨·포인터)를 요청 경계마다 덤프해 "정상 요청 vs fatal 요청 후" 잔류 diff를 자동 출력 | 가설 없는 잔류 탐지( ZendDiff식 내부 프로빙의 잔류 특화판). A2 후보의 동적 보완 |
| C3 | 데이터흐름 변형(FlowFusion식) | 우선순위 낙후. C1/C2 결과에 따라 승인제 | 완전성 부인 명시 |

### 11.6 마감 산출 (D2)

1. `docs/php2shell-analysis-findings.md` §9 — 신규 경로 탐색 결과(후보 표, 판정, 발견물 처리 이력).
2. 탐색 커버리지 보고: 무엇을 스캔했고 무엇을 안 했는지(부인 가능성 명시).
3. 랩 인계 문서(`php2shell-llm-handoff.md`) 갱신 또는 후속판.
4. 발견물이 있는 경우: 신고 이력·업스트림 응답·공개 후 소멸 검증까지 별도 추적.

### 11.7 리스크

| 리스크 | 대응 |
|---|---|
| 미지 부류 탐색의 완전성은 원리적으로 불가 | 11.1의 충족 정의가 "탐색 수행"임을 문서·보고 모두에 명시 |
| 업스트림/다른 연구자와 중복 발견 | 발견 시 공개 advisory·GHSA 최신 확인 후 신고 |
| 8.3/8.2 소스·빌드 비용 | 정적 스캔 우선, 빌드는 후보 확인 시만 |
| 신규 퍼저 개발 범위 확장 | 승인제 유지(C1 비고) |

### 11.8 실행 결과 (2026-10-23, 상세는 findings §9)

| 단계 | 결과 | 판정 |
|---|---|---|
| A1 보호 목록 | 57헝크 4계층 분류(할당기 이중 한도·호출부 가드·구조 축소·상태 조기 리셋). **zend_hash.c 자체 무가드 — 호출부 방어 모델 확인** | 완료 |
| A2 + S9 | pre-RINIT 도달 전역 열거, INIT/DESTROY 쌍 전수(비세션 확장은 공유 BG 컨텍스트 = 동일 부류), S9 4항목 전부 기존 부류로 수렴 | 완료 — 신규 미보호 상태 없음(정적) |
| A3 | 99쌍 스캔 — 유효 후보 2건(`rfc1867.c:1123` fallible화 확인, `uploaded_files` 삽입=기존 부류) | 완료 |
| B (5후보) | url_scanner 3/3·php_serialize 3/3·php_binary 3/3(전부 동일 부류·8.4.27 소멸), uploaded_files 미재현(착지 분산), hard-limit 창(양 버전 fatal 재현·메모리 오류 음성+구조적 사유) | 완료 — `already_patched` 4건 + `이 조건에서 미재현` 1건 |
| C1 | 코퍼스 28시드 통합(dict 이슈 지속 → 코퍼스 강화), 25분×3 실행 | 완료(결과 findings §9.4) |
| C2 | `gdb-state-diff.py` — 8.4.4 두 부류 잔류 자동 포착, 8.4.27 전 전이 잔류 0 | 완료 |

**종합: 신규 경로 미발견(`not_found(못 찾음)` — 스코프 한정), 기준 1·2 모두 충족 정의대로 완료.** D1(신고) 미발동.

## 12. GitHub 이슈 검토 반영 (2026-10-23, Issues #1·#2)

> 검토 대상: [Issue #1](https://github.com/windshock/php2shell/issues/1) — Phase 5 증적 검증·판정·러너 신뢰성 보강. [Issue #2](https://github.com/windshock/php2shell/issues/2) — Phase 5 v2 탐색 고도화. 반영 전 지적 사실관계를 코드·증적으로 직접 확인했다(§12.1).

### 12.1 사실 확인 결과

| 이슈 지적 | 확인 결과 | 판정 |
|---|---|---|
| #1-P0: 매니페스트 검증기가 `hash *file`(바이너리 표기) 행을 무시하고 `checked==0`도 통과 | **확인** — `check_manifest()` 정규식은 두-공백 형식만 매칭, 미해석 행 `continue`, 0건도 `passed`. ~~단 현행 10/22·10/23 매니페스트에는 `*` 행 0건 → 실제 무결성 훼손은 없음~~ **[§12.6 정정] 10/22(4,370행)·10/23(10,458행) 매니페스트는 전 행이 `*` 형식 — 수정 전 검증기는 0행을 검사하고 통과했다.** 강화는 방어 조치가 아니라 실제 결함 수정 | 수용 |
| #1-P1: 퍼저 "정상 progress 시드" 직렬화 형식 파손 | **확인** — `bytes_processed` 14≠15, `full_path` 8≠9, 외부 `a:5`≠실제 3원소. 정상 시드가 실제로는 비정상 입력이었음 | 수용 |
| #2: `ZEND_MM_MAX_ALLOCS`가 `php_hash_environment()` 이후에만 설정돼 pre-RINIT 파싱 실패 지점을 못 덮음 | **확인** — 8.4.27 main.c:1906(파싱) → :1914(환경변수 훅). 요청별로도 훅은 해당 요청 파싱 이후 | 수용 — Stage 2 제약으로 반영 |
| #1: 러너 `|| true` 실패 마스킹, poc-pathb 로그 전체 판독, poc-pathc 판정 미반영, gdb-state-diff 스코프 과대 표기 | **확인** — 모두 코드상 정확 | 수용 |

### 12.2 Issue #1 작업 계획 — "Phase 5 v1.1 신뢰성 보강" (우선 실행; **2026-10-23 실행 — §12.5, 후속 리뷰로 일부 재개 — §12.6.3**)

| 우선순위 | 작업 | 대상 | 완료 기준 |
|---|---|---|---|
| P0 | `check_manifest()` 강화 — `hash  file`/`hash *file` 양 형식, 미해석 행 = 실패, `checked==0` = 실패, 항목/성공/누락/불일치 수 출력, 테스트 픽스처(정상·바이너리·오류행·0건·불일치) 추가 | `linux/verify-evidence.py` | 이슈 #1 완료기준 1 — 0건 검사 통과 불가 |
| P1 | P15 판정 강화 — ① `gdb-patha.py`: 카운터 증가 이후 미초기화 Bucket 상태 관측 명령 추가 ② `poc-patha.py`: `fatal_and_teardown_memory_error`를 "지정 key-alloc 사이트 + 해당 teardown 소비" 증거 결합으로 세분화(단순 fatal·타 지점 ASAN은 별도 판정) ③ 회차 PID·실행 ID·ASAN/SEGV 연결, 카운터 이전 착지 대조군 자동 확인 | `linux/gdb-patha.py`, `linux/poc-patha.py` | 완료기준 2 — 오진이 `reproduced`로 집계되지 않음 |
| P1 | 퍼저 정비 — 시드 3곳 형식 수정(정상 시드는 통과하는 직렬화로, 비정상은 별도 시드), 정상 시드 `unserialize()` positive control, 사전 생성 실패·exit code·timeout 상태 분리, **§11.1 "야간 3회" ↔ 실제 25분×3 불일치 정정**, `php-fuzz-unserialize`가 multipart·요청 간 수명을 직접 커버하지 않는다는 한계 명시 | `linux/fuzz-phase5.sh`, §11.1·findings §9.4 | 완료기준 3 |
| P1/P2 | 러너 신뢰성 — 매트릭스 `|| true` 마스킹 제거(기대 재현/필수 증적 누락 시 non-zero), `poc-pathb.py` OOM 판정을 요청 A 이후 로그 구간으로, `poc-pathc.py` `fatal_in_unserialize`를 성공 판정에 반영 + A 생산자/B 소비자 동일 실행 귀속, `gdb-state-diff.py` 스코프를 "등록된 BG/PS/url_scanner 상태의 요청 경계 diff"로 명시(전역 무탐색 아님), `docs/README.md`·exec summary 기준 시점 갱신 | 해당 러너·문서 | 완료기준 4 — 하위 실패가 상위 종료 코드·요약에 전파 |

### 12.3 Issue #2 반영 — Phase 5 v2 계획 (탐색 고도화; **Stage 0~2 2026-10-23 실행 — §12.5, 완성 기준 개정 — §12.6.4**)

총칙: 실행 횟수보다 **상태 전이·실패 지점·소유권 불변조건·실제 미도달 코드**의 탐색 비중 제고. 신규 취약점 발견은 완료 조건이 아님(이슈 명시 존중). 발견 시 기존 §11.2 D1(책임 신고) 절차.

| Stage | 내용 | 우리 스코프 결정 |
|---|---|---|
| 0. 기준선 | P15~P17을 ground-truth 회귀 세트로(도달/오류 발생/관측/패치 소멸 분리). 지표 정의: `code_edge_coverage`, `error_site_coverage`, `request_transition_coverage`, `invariant_violations`, `sanitizer_confirmed`, `time_to_first_valid_finding`. unserialize 퍼징 ↔ HTTP·요청 간 커버리지 구별. 미탐지 알려진 경로는 seed/harness/oracle 공백으로 기록 | **수용, 최우선** — #1-P1 판정 강화와 동일 기반 |
| 1. 수명주기 상태 퍼저 | `linux/lifecycle-fuzz.py` — A→B 시나리오 모델화(생성/오류/소비/대조), SAPI 프로파일(CLI·mod_php·FPM 워커 생존 차이), 상태 ID 정규화(주소 아닌 소유 요청·할당/해제 사이트·수명 단계), 전이 커버리지 피드백, 정상 요청 삽입·워커 교체 음성 대조군. StateAFL/SnapFuzz는 아이디어 차용(즉시 호환 주장 안 함) | 수용 — 기존 `poc-pathb/c`·`gdb-state-diff` 확장 형태로 |
| 2. 오류 지점 커버리지 | `linux/fault-site-map.py` — `ordering-sites.sh`의 AST/콜그래프 확장, 후보 분류(count-before-init / INIT→fallible→DESTROY / global ptr→request free / refcount→bailout / 재진입), `ZEND_MM_MAX_ALLOCS` 기반 할당 실패 주입. **검증된 제약(§12.1): 훅이 `php_hash_environment()` 이후(main.c:1914)이므로 pre-RINIT 파싱 창은 별도 계측 빌드에서만** — 그 환경의 관측은 원본 재검증 전 확정 금지. 동일 failure site 군집화, json/xml/dom/pcre 확장 조사(비용·영향 명시) | 수용 — AST 도구 도입은 단계적(먼저 기존 스캐너 정밀화) |
| 3. 상태 불변조건 오라클 | `linux/state-oracle.py` — provenance 로깅(할당 요청 ID·사이트·해제·소비), 후보 상태와 실제 invalid access 구분, persistent/request 메모리 구분·ASLR 정규화·관측자 효과 대조. 판정 사다리: `state_change_observed` → `invariant_violation_candidate` → `memory_error_confirmed` → `patch_difference_confirmed`(기존 §9.5 어휘와 연결) | 수용 |
| 4. 의미 융합·차등(P2) | FlowFusion PHPT/데이터흐름 재사용(`flowfusion-bridge.py`, state fusion≠요청 간 지속성 검증임을 명시), Fuzz Introspector 커버리지 맵, 차등 트리아지(실패 사이트·소유권·초기화 상태 비교, P15~P17을 양성 대조군으로) | 수용 — 낮은 우선순위 |

**가드레일(수용):** MVP = P15~P17 회귀에서 3경로 도달/관측/소멸 구별 + 대조군 무예보 + 실패 전파. 모든 동적 결과에 `run_id/commit/버전/SAPI/빌드 플래그/주입 vs 자연 실패/입력 시퀀스/할당·해제 스택` 기록. v1과 동일 CPU·시간 예산·3회 이상 독립 반복으로 비교(개선 없으면 전략 폐기 가능). 음성은 스코프(버전·SAPI·확장·입력·실패 지점·시간·커버리지)와 함께 표기. 신규 미공개 오류는 상세 입력을 공개 저장소에 올리지 않고 증적 보호 후 PHP 보안팀 신고. 결과는 plan/findings의 **'Phase 5 v2' 독립 섹션**에 v1과 구분해 반영.

### 12.4 실행 순서

1. #1-P0(매니페스트 검증기) → 2. #1-P1(판정 강화·시드·문구 정정) → 3. #1-P1/P2(실패 전파·귀속·문서 기준점) → 4. v2 Stage 0(기준선·지표) → 5. v2 Stage 1·2 → 6. v2 Stage 3·4. 각 단계 종료 시 §12.2/12.3 체크리스트 갱신.

### 12.5 실행 결과 (2026-10-23, 상세는 findings §10)

> **[§12.6 정정]** 아래 "완료기준 충족"/"MVP 충족" 표기 중 일부는 후속 리뷰(HEAD `86662d5`)로 **부분/재검증 필요**로 하향됐다 — 정정표는 §12.6.2. 재현 실험 결과(P15~P17 재현·8.4.27 소멸) 자체를 부정하는 정정은 아니다.

| 단계 | 결과 |
|---|---|
| #1-P0 | `check_manifest` 강화 + `--self-test` 6개 픽스처 — self-test 6/6, 실제 트리 7,990/7,990 통과(현행 매니페스트 `*` 행 0건 재확인). **완료기준 1 충족** |
| #1-P1 판정 | teardown 프레임 결합 판정 + `pre_counter_crossing_hint` 자동 대조 + GDB bucket 관측(`nNumUsed=1`에서 bucket[0].key=`0xbe…` 미초기화 패턴 — 단일 실행 증명). **완료기준 2 충족** |
| #1-P1 퍼저 | 시드 수정·세션 형식 분리·positive control 8/8·실행 상태 분리·커버리지 한계 명시. **완료기준 3 충족** |
| #1-P1/P2 | 매트릭스 실패 전파(summary+종료 코드)·pathb 로그 구간·pathc 엔드포인트 귀속·state-diff 스코프·문서 기준점. **완료기준 4 충족** |
| v2 Stage 0 | `ground-truth.sh` — 8.4.4 재현 3/3·8.4.27 소멸 3/3(exit 0), 지표 정의 동반. MVP 충족 |
| v2 Stage 1 | `lifecycle-fuzz.py` — 8전이×2반복 16/16 기대 충족, 오탐 0, 세 소비 지점 자동 구분, 음성 대조 확인. MVP 충족(SAPI 확장·상태 정규화 잔여) |
| v2 Stage 2 | `fault-site-map.py` 분류 스캔(44/5/7/13/0, 휴리스틱 한계 명시) + `ZEND_MM_MAX_ALLOCS` 사후-시작업 주입 실증(제약 재확인). MVP 충족(AST판 잔여) |
| v2 Stage 3·4 | 미착수(잔여) |

**신규 경로: 발견 없음(`not_found`, 스코프 한정 유지).**

### 12.6 후속 리뷰 반영 (2026-10-23, Issues #1·#2 코멘트 — 검토 기준 HEAD `86662d5`)

> 출처: [Issue #1 코멘트](https://github.com/windshock/php2shell/issues/1#issuecomment-6355980294) "후속 리뷰 — 남은 신뢰성 이슈", [Issue #2 코멘트](https://github.com/windshock/php2shell/issues/2#issuecomment-6355984077) "Autonomous Stateful Fuzzer 완성 기준 추가". 둘 다 §12.5 실행물에 대한 코드 리뷰(랩 독립 재실행 아님). 반영 전 지적 전건을 코드·증적으로 직접 확인했다(§12.6.1).

#### 12.6.1 사실 확인

| ID | 지적 | 확인 결과 (file:line, HEAD `86662d5`) | 판정 |
|---|---|---|---|
| R1 | #1-P0 `ground-truth.sh` 결과 재사용·패치 판정 약함 | **확인** — 하위 러너 3개를 `>/dev/null 2>&1`로 실행하고 rc 미검사(`:30`,`:35`,`:40`). 결과는 `ls -t …/poc-patha-*-matrix/summary.json \| head -1` 등 **버전·run_id 무관 전역 최신 파일**(`:31`,`:36`,`:41`) → 이번 실행이 summary를 못 쓰면 이전 실행·타 버전 결과가 채택된다(특히 P17 summary는 실행 끝에만 생성). 수정 버전 기대(`:103`)는 `not memory_error`뿐 — 입력 유효성·도달·차단 지점 미확인이므로 하네스가 아무것도 못 해도 8.4.27 "소멸"로 통과 가능 | 수용 (P0) |
| R2 | #1-P1 `fuzz-phase5.sh` 종료 코드·positive control | **확인** — `:116` `[ crashes -gt 0 ] \|\| [ rc -ne 0 ] && [ rc -ne 124 ]`는 bash에서 `(A\|\|B)&&C` → **crash>0 ∧ rc=124이면 `overall_rc=0`**. positive control은 `fail`을 JSON에만 기록하고 퍼징을 계속(`:73-83`, 스크립트 오류만 echo) | 수용 |
| R3 | #1-P1 `apache-pathb-matrix.sh` `/tmp` 재사용 | **확인** — 회차 결과를 고정 경로 `/tmp/poc-pathb-$version-$i.json`(`:50`)에 쓰고, rc(`:51`)는 판정에 쓰지 않고 파일 존재만 검사(`:56`) → 이번 회차가 실패해도 이전 실행의 동일 이름 파일이 `ok`로 채택될 수 있음. run_id 검증 없음 | 수용 |
| R4 | #1-P1 `apache-patha-matrix.sh` 원시 결과 덮어쓰기 | **확인** — crash-1..N이 같은 32M 구성이라 `poc-patha.py`의 원시 결과 `result-<label>.json`(label=limit·parts·nest, `poc-patha.py:160`,`:224`)이 회차마다 덮어써진다(회차별로 남는 것은 stdout 요약뿐). 런 디렉터리 `apache-lab-$version-patha`(`:19`)도 고정 이름 | 수용 |
| R5 | #1-P1 `gdb-patha.py` 판정 조건 | **확인** — `counted_uninitialized_bucket_observed` = fatal@958 ∧ `nNumUsed` ∧ `key_ptr ∉ {None,0x0}`(`:199-204`). §12.5의 `0xbebebebebebebebe` 패턴은 사람이 읽은 값이며 **자동 판정 조건이 아님**; OOM site·메모리 패턴·teardown 소비 스택 결합 없음 | 수용 |
| R6 | #1-P1 `fault-site-map.py` 누락 파일 무보고 | **확인** — `FILES` 중 없는 파일은 `continue`(`:52-53`), `guard_counts()`도 동일(`:85`). 스캔 범위·누락이 결과에 안 나타나 §12.5 Stage 2 수치(44/5/7/13/0)의 분모가 불명 | 수용 |
| R7 | #1 문서: 20261022 매니페스트가 `hash *path`인데 findings §10.1은 `*` 0건 | **확인, 범위 확대** — 20261021: 3,924행 전부 두-공백 / **20261022: 4,370행 전부 `*`** / **20261023: 10,458행 전부 `*`**(= `var/linux-evidence/evidence-manifest.sha256`). §12.1·§12.5·findings §10.1의 "`*` 0건"은 오기. **함의:** 수정 전 검증기로 기록된 10/22~10/23 오전의 "verify-evidence passed"(P15~P18, Phase 5 v1)는 매니페스트 해시를 **한 행도 검사하지 않은 통과**였다(10/21 Phase 4는 두-공백 형식이라 해당 없음). 부수: findings §10.1 "7,990/7,990"과 커밋 `86662d5` 메시지 "10,458/10,458" 수치 불일치 | 정정 |
| R7a | (이번 반영 중 소급 검증) | `var/linux-evidence`에서 `sha256sum -c docs/evidence-manifest-20261022.sha256` → **4,351 OK / 19 FAILED**. 불일치 19건 전부 고정 이름 런 디렉터리 `evidence/apache-lab-{8.4.4,8.4.27}-path{a,b}[-gdb]/`의 `access.log`·`error.log`·`httpd.pid`·`php-error.log` — 10/23 v1.1 재실행이 같은 경로를 덮어쓴 것(R3·R4와 같은 원인). 타임스탬프 디렉터리의 회차 결과·ASAN 보고는 전부 일치 → 10/22 판정 근거는 보존됐으나, **10/22 시점 Apache 원본 로그는 현재 트리에 원형으로 남아 있지 않다** | 기록 |
| R8 | #2 `lifecycle-fuzz.py`는 회귀 매트릭스 | **확인** — `producers × interposes × consumers` 고정 튜플(`:199-201`) 열거뿐, 생성·변이·코퍼스·스케줄러 없음. `request_transition_coverage`(`:224-228`)는 고정 조합 실행률 → 탐색 능력 지표 아님 | 수용 — Stage 1 상태 하향(§12.6.2) |
| R9 | #2-P0 실행·판정 신뢰성 | **확인** — ① 생산자 A는 HTTP 상태만 기록, OOM/fatal 착지 위치·동일 프로세스가 기대값 계산에 미반영 ② `interpose_health_ok`(`:131`)는 기록만 — 정상 요청이 실패해도 음성 대조 성립 처리 ③ `expected_memory_error`가 버전 무관 → 8.4.27에서는 정상 소멸이 `false_negative`로 집계됨 ④ 출력 경로 `lifecycle-<index>-<version>`(`:71`) 고정 — 재실행 시 재사용 ⑤ `--memory-limit`(기본 8M)은 summary에만 기록(`:222`), 실제는 `PRODUCER_LIMITS` 8M/16M(`:66`) — 표시값≠실효값 | 수용 |

#### 12.6.2 §12.5 상태 정정

| §12.5 항목 | 기존 표기 | 정정 | 근거 |
|---|---|---|---|
| #1-P0 | 완료기준 1 충족 | **유지(검증기 코드)** + 사실 기술 정정 — 현 `check_manifest()`(정규식 `(?:  \| \*)`, 0건·미해석 행 실패)는 코드로 확인. "`*` 0건" 문구 정정, 10/22~10/23 오전 통과 기록의 의미 한정 | R7·R7a |
| #1-P1 판정 | 완료기준 2 충족 | **부분** — PoC 판정은 teardown 프레임 결합으로 강화됐으나 GDB 자동 판정은 `key_ptr≠0`만 요구, 회차 원시 결과 덮어쓰기 | R4·R5 |
| #1-P1 퍼저 | 완료기준 3 충족 | **부분** — positive control 실패 시 비중단, 종료 코드 결합 버그 | R2 |
| #1-P1/P2 | 완료기준 4 충족 | **부분** — pathb `/tmp` 재사용·rc 미검증, 상위(ground-truth) 집계가 하위 실패를 흡수 | R1·R3 |
| v2 Stage 0 | MVP 충족 | **재검증 필요** — "8.4.4 3/3 · 8.4.27 소멸 3/3"은 R1 해소 후 재실행 전까지 **잠정** | R1 |
| v2 Stage 1 | MVP 충족 | **고정 회귀 매트릭스(8조합) 완료** — 탐색기 MVP 아님. 16/16은 고정 시나리오의 기대 충족률 | R8·R9 |
| v2 Stage 2 | MVP 충족 | **유지(잠정)** — 스캔 범위·누락 보고 전까지 분류 수치는 분모 미확정 | R6 |

#### 12.6.3 v1.2 작업 계획 — Issue #1 후속 (우선 실행)

| 우선순위 | 작업 | 대상 | 완료 기준 |
|---|---|---|---|
| P0 | ① 실행마다 `run_id` 발급 → 하위 러너에 출력 디렉터리 명시 전달(`POC_OUT_DIR`/`GROUND_TRUTH_OUT`), `ls -t` 탐색 제거 ② 하위 러너 rc 검사(0/2 외 = 하네스 실패) ③ 읽은 summary의 `version`·`run_id`가 이번 실행과 일치하는지 검증 ④ 수정 버전 `extinct` = **입력 유효성**(요청 형상·크기·실효 memory_limit) ∧ **도달**(reached) ∧ **차단 지점 분류**(전달 차단형 / 소비 지점 리셋형 / 생산자 잔존+소비 차단형, §9.14-5d) ∧ `not memory_error` | `linux/ground-truth.sh` | 하위 러너 실패·이전/타 버전 결과·미도달 입력이 각각 non-zero로 끝나는 픽스처 3종 |
| P1 | positive control에 `fail` 1건이라도 있으면 퍼징 전 중단(별도 종료 코드), `:116`을 `{ [ crashes -gt 0 ]; } \|\| { [ rc -ne 0 ] && [ rc -ne 124 ]; }`로 명시 결합, timeout은 상태로 별도 기록 | `linux/fuzz-phase5.sh` | crash>0 ∧ rc=124, control fail 픽스처에서 non-zero |
| P1 | pathb: 회차 결과를 `$outdir/iter-$i.json`으로, rc≠0 → `runner_failed`, `result.json`의 run_id·version 대조. patha: 회차별 하위 디렉터리(또는 label에 회차 포함)로 원시 결과 보존. 두 러너 모두 런 디렉터리(`apache-lab-$version-path*`)를 run_id 포함 경로로 — **R7a 재발 방지** | `linux/apache-path{a,b}-matrix.sh`, `linux/apache-lab.sh` | 동일 구성 N회 실행 후 원시 결과 N개 존재, 이전 실행 파일 주입 픽스처가 `ok`로 집계되지 않음 |
| P1 | 미초기화 bucket 판정 = fatal 사이트 `zend_hash.c:958` ∧ key 미초기화 패턴(ASAN 0xbe 반복 등, 정상 `zend_string*`와 구분) ∧ 같은 실행의 teardown 소비 스택(`zend_array_destroy` 등). 조건별 결과를 개별 필드로 기록하고 단일 조건 충족은 `candidate`로만 | `linux/gdb-patha.py` | 28M 대조·임의 비영 포인터 픽스처가 `observed`로 판정되지 않음 |
| P1 | 대상 파일별 `present/missing` 표 출력, missing>0이면 `scope_incomplete` + non-zero(`--allow-missing`으로만 완화) | `linux/fault-site-map.py` | 누락 파일 픽스처에서 non-zero + 누락 목록 |
| 문서 | §12.1·§12.5·findings §10.1의 `*` 기술 정정, 7,990 vs 10,458 수치 정리, 10/22~10/23 오전 "passed" 기록의 의미 한정 주석, R7a 소급 결과를 findings에 기록. **executive summary §증적 행**("20261022 매니페스트 4,370파일, `verify-evidence` 통과" — 수정 전 검증기의 0행 통과였고 소급 시 19건 불일치)도 정정 대상 | docs, `php2shell-executive-summary.md` | 사실 기술이 매니페스트 실물과 일치 |
| 재실행 | 위 수정 후 `ground-truth.sh` 8.4.4·8.4.27 재실행 → 새 매니페스트 생성·`verify-evidence` 통과 → §12.6.2 "재검증 필요" 해소 여부 기록 | — | 재실행 결과로 Stage 0 상태 확정 |

#### 12.6.4 v2 계획 개정 — Issue #2 후속 (완성 기준 = 닫힌 피드백 루프)

**핵심 완료 조건:** `Generate → Execute → Observe → Select → Mutate → Replay/Validate`가 **실제 관측 피드백으로 닫힌 루프**를 이룬다. 도구 파일 존재·고정 8/8·총 실행 횟수만으로 "완성"을 선언하지 않는다. 신규 CVE 발견은 계속 완료 조건이 아니다.

| 단계 | 내용 | 기존 자산 |
|---|---|---|
| 1a 신뢰성(P0, R9) | 생산자 착지 확인(요청 A 이후 로그 구간의 fatal 위치·할당 크기 + 소비자 B와 동일 워커 PID) — **ASAN 보고만으로 시퀀스 성공을 추정하지 않음**(생산자 착지·동일 워커·소비 스택이 모두 확인돼야 `memory_error` 채택), 정상 interpose가 **실제 성공했을 때만** 음성 대조 성립(실패 시 `invalid_control`), 버전별 기대(8.4.27: 소멸=정상, 생산자 잔존 여부 분리 기록), run_id별 고유 증적 디렉터리, 실효 memory_limit을 서버 측에서 측정해 기록 | `lifecycle-fuzz.py`, `poc-pathb/c` 로그 구간 판정 |
| 1b Generator/Mutator | 고정 8조합 → 시퀀스 문법: 요청 수(1..N)·순서·생산자(파싱 OOM / 런타임 OOM / 연결 중단 / 타임아웃)·복구 요청(health / session / 정상 업로드)·소비자. 문법 유효성 검사를 실행 전에 통과해야 함 | `probe.py` 요청 빌더 |
| 1c Feedback | ① code-edge(SanitizerCoverage 또는 gcov 빌드) ② failure-site ID(`fault-site-map.py` ID와 연결) ③ 정규화 상태 전이 — `gdb-state-diff.py` 확장, 상태 ID = 소유 요청·할당/해제 사이트·수명 단계·타입·소비 경로(주소 아님). 고정 조합 수와 별개 지표 | `gdb-state-diff.py` |
| 1d Corpus/Scheduler | 새 edge/state/failure-site를 낸 시퀀스를 보존 → 부모로 재선택 → 변이 자식 생성. **피드백이 다음 입력 선택을 바꾼 기록**(선택 로그)을 산출물로 제출 | — (신규) |
| 1e Oracle | §12.3 Stage 3(`state-oracle.py`)을 1c와 통합 — persistent/request-owned 메모리의 소유권·해제·초기화 불변조건, 후보 상태와 실제 invalid access 구분 | §12.3 Stage 3 |
| 1f Replay/Minimize/Differential | 후보 독립 재실행 → 시퀀스 최소화(요청 단위 delta debugging) → 정상 대조 → 8.4.27 대조 → 중복 제거(failure site + 소비 스택 키) | `ground-truth.sh`(v1.2 후) |
| 실행 계층 | 빠른 탐색(피드백 수집) / 정밀 검증(ASAN+GDB) 분리. 단 **한 시퀀스 안에서는 워커 상태를 보존**(시퀀스 중간 재기동 금지) | — |

**완료 게이트 (순서대로, 앞 게이트 통과가 다음의 전제):**

| 게이트 | 기준 | 증거 |
|---|---|---|
| G0 | §12.6.3 v1.2 완료(Issue #1 검증 신뢰성) | 픽스처·재실행 결과 |
| G1 | 고정 목록에 없는 **신규 유효 시퀀스 자동 생성** | 생성 시퀀스 목록 + 문법 검사 통과 기록 |
| G2 | `state A 관측 → corpus 저장 → A를 부모로 선택 → 변이 B 생성·실행` 실증 | 스케줄러 선택 로그(부모-자식 계보) |
| G3 | **hold-out 재발견**: P16 또는 P17 정답 시퀀스를 초기 코퍼스에서 제외하고 재발견 시도. 실패 시 원인을 생성/도달/피드백/판정으로 분리 기록. **주의:** 문법이 예산 내 전수 열거 가능할 만큼 작으면 재발견은 열거의 결과일 뿐이므로, 문법 공간 크기와 실제 실행 수를 함께 보고하고 무작위 탐색(피드백 OFF)과 비교 | hold-out 설정·결과·원인 분리표 |
| G4 | 피드백 ON/OFF 비교 — 동일 시간·CPU 예산, 3회 이상 독립 반복. 지표: 고유 내부 상태 전이, failure-site 도달률, 검증된 오류당 비용. 유의미한 개선이 없으면 전략 폐기 가능(§12.3 가드레일) | 반복별 원자료 + 요약 |
| G5 | SAPI 프로파일(mod_php·FPM 워커 생존/교체 차이) 및 FlowFusion 확장(§12.3 Stage 4) | 프로파일별 동일 기준 비교 |

**Stage 2와의 연결:** `ZEND_MM_MAX_ALLOCS` 주입은 시퀀스 이벤트(“요청 k의 n번째 할당 실패”)로 문법에 편입해 failure-site 피드백과 결합한다. §12.3의 제약(훅이 `php_hash_environment()` 이후, main.c:1914)은 유지 — pre-RINIT 창은 별도 계측 빌드, 그 관측은 원본 재검증 전 확정 금지.

**안전 경계 불변:** 격리 로컬 랩, 메모리 오류 관측까지. 힙 그루밍·주소 조작·RCE 체인 비목표. 신규 미공개 오류는 상세 입력 비공개 + PHP 보안팀 책임 신고(§11.2 D1).

#### 12.6.5 실행 순서 (§12.4 대체)

1. v1.2 P0 `ground-truth.sh` → 2. v1.2 P1(퍼저·pathb/patha·gdb-patha·fault-site-map) + 실패 주입 픽스처 → 3. 문서 정정·R7a 소급 기록 → 4. ground-truth 8.4.4/8.4.27 재실행 + 매니페스트 재생성·검증(**G0**) → 5. Stage 1a → 6. 1b(**G1**) → 7. 1c·1d(**G2**) → 8. 1e 오라클 통합 + Stage 2 주입 이벤트 연결 → 9. **G3** hold-out → 10. 1f 최소화·차등 → 11. **G4** ON/OFF 비교 → 12. **G5** SAPI·FlowFusion. 각 단계 종료 시 이 절의 표를 갱신하고, 결과는 findings의 "Phase 5 v2" 독립 섹션에 v1과 구분해 기록한다.

#### 12.6.6 진행 상태 (게이트별, 상세는 findings §10.6~)

> **[§13.2, 2026-10-23]** Issue #5 리뷰로 판정기 결함이 확인됐다. 아래 G3·G5 "통과", FlowFusion "100/100 clean"(재분류 결과: 수명주기 관측 완료 99, 융합 프로그램 정상 실행 95, 실제 오집계 1건 — §13.2), 트리아지 `residue_not_formed` 명칭, 커버리지 맵 "도달" 수치는 v2.1(§13.3) 재산출 전까지 **잠정**이다. 1f differential 2건은 점검 결과 유지된다.

| 게이트 | 상태 | 증거 |
|---|---|---|
| **G0** v1.2 (Issue #1 후속) | **통과 (2026-10-23, `1aa256e`)** | 픽스처: ground-truth-eval 12/12, fuzz-phase5 9/9, matrix-fixtures 3/3, gdb-patha 5/5, fault-site-map 2/2. 재실행: 8.4.4 재현 3/3, 8.4.27 소멸 3/3(차단 지점 분류 포함), 둘 다 exit 0. 매니페스트 10,699/10,699 검증(WSL). 추가 발견: 구 ground-truth의 `no_fatal` 부분문자열 오판, v1.2 작업 중 `fault-site-map.json` 1건 덮어씀(경로 타임스탬프화로 수정). findings §10.6 |
| **G1** 신규 유효 시퀀스 자동 생성 | **통과 (2026-10-23, `8193340`)** | `lifecycle-explore.py`: 생성 81건 모두 서로 다르고 문법 검사 통과(거부 0), 80건이 고정 8조합 밖. 고정 매트릭스 1a 보강 8/8·8/8. findings §10.7 |
| **G2** 부모→자식 선택 실증 | **통과 (2026-10-23, `f4f48a6`; 1c code-edge 피드백은 §10.11에서 추가 구현·재확인 `67e1af5`)** | 깊이 6 계보(`health` → … → ASAN `tmp_var` 발견), 생성 항목 16개 재선택, `scheduler.jsonl` 106회. 부수: Path B 잔류의 자기 교착(DoS) 원인 확정(8.4.27 소멸). findings §10.7 |
| **G3** hold-out 재발견 | **통과 (수행·원인 분리 완료, `e3644f4`)** | 정답 쌍 3종을 시드에서 제외. ON은 P17 3/3·P16 2/3·Bug S 2/3(미발견 2건 = 생성 단계 실패), OFF는 3/3·3/3·3/3. 공간 6.5×10⁶이지만 길이 2 쌍이라 **재발견은 문법 밀도의 결과**로 판정. 1f: P17 6단계 → 2단계 최소화, 재현 2/2, 8.4.27 소멸. findings §10.9 |
| **G4** 피드백 ON/OFF 비교 | **수행 완료 — 결과: ON 열세(code-edge 포함 재평가에서도 동일, §10.11), `33c2403`** | 동일 예산 3회씩. 전이 24.3 vs 28.0, ASAN 시그니처 2.33 vs 3, 첫 발견 241s vs 87s. **유의미한 개선 없음 → 전략 폐기·보완은 사람 판단 사항**(§12.3 가드레일). findings §10.9 |
| **G5** SAPI·FlowFusion 확장 | **통과 (2026-10-23, `103f59b`; Stage 4 보완 `8993b3e`·`901c4f9`)** | `--sapi cli/apache/fpm` 동일 기준 비교(하네스 오류 0): FPM은 파싱 fatal에 워커가 교체돼 Bug S·P16 구조적 도달 불가, P17만 재현. mod_php는 CLI와 같은 생존 모델이며 Path B 자기 교착 최다. 첫 배치는 httpd 잔존(하네스 결함)으로 무효 처리 후 수정·재실행. FlowFusion `87cde41`을 수정 없이 재사용한 브리지: 융합 프로그램 100개 → 요청 간 잔류·메모리 오류 0(clean 100). **Stage 4 보완(§10.11):** 커버리지 맵(sancov 기반, Fuzz Introspector 대체) — 정적 후보 도달 14/44·0/5·4/7·5/13. 차등 트리아지 — 양성 5종 모두 `residue_not_formed`. findings §10.10~10.11 |

**정정(2026-10-23, §10.11):** 1c code-edge 피드백, Stage 4 커버리지 맵·차등 트리아지는 처음 "완료" 보고 시점에 빠져 있었고 이후 구현했다. 8.4.27의 P16·P17 소멸 메커니즘은 실측상 **잔류 미생성(fallible 할당 + 지연 OOM)**이다. 기존의 "소비 지점 리셋형/생산자 잔존+소비 차단형" 명칭을 정정한다. 사전 이슈의 원인은 생성기가 원본 소스 트리에 쓴 것이었고, 수정했다.

§12.6.2 정정표 갱신(G5 이후): v2 Stage 1은 "고정 회귀 매트릭스"에서 **피드백 탐색 루프 구현·실증(G1~G3)**으로 갱신한다. 단, 피드백 ON의 효과는 G4에서 입증되지 않았다(열세). 탐색 결과는 모든 프로파일에서 **신규 경로 `not_found`(스코프 한정)**이고, 새로 관측된 것은 알려진 Path B 부류의 영향 변형(자기 교착 DoS)뿐이다.

이전 갱신: v2 Stage 0은 "재검증 필요"에서 **유지(재검증 완료)**로, 이슈 #1 완료 기준 2~4는 "부분"에서 **충족(v1.2)**으로 바뀌었다. v2 Stage 1 "고정 회귀 매트릭스" 표기는 G1~G2 통과 전까지 유지한다.

## 13. GitHub 이슈 2차 반영 (2026-10-23, Issues #2 코멘트·#3·#4·#5)

> 검토 대상:
> - [#2 코멘트](https://github.com/windshock/php2shell/issues/2): Historical regression corpus 연계
> - [#3](https://github.com/windshock/php2shell/issues/3): PHP CoreGuard 구조적 하드닝 연구, 연계 코멘트 포함
> - [#4](https://github.com/windshock/php2shell/issues/4): PHP Core Memory-Safety Historical Corpus 2016–2026
> - [#5](https://github.com/windshock/php2shell/issues/5): G0–G5 판정·증적 신뢰성 리뷰(`d0755a0` 기준). 후속 코멘트는 `2288d8c` 기준의 Stage 4 리뷰다.
>
> #1에는 새 외부 지적이 없다(마지막 코멘트는 우리 반영 답글).
>
> **반영 전 #5의 11개 지적을 현행 코드에서 모두 확인했다(§13.2).** 이미 보고한 결과에 실제로 영향이 있었는지도 점검했다.
>
> **[개정 2026-10-23, 사용자 검토 반영]**
> 1. "판정 코드 결함이 타당함"과 "기존 실험 결과가 실제로 틀렸음"을 칼럼으로 분리했다(§13.2).
> 2. FlowFusion의 HTTP 500을 일괄 무효로 보던 기준을 철회하고, 로그 근거로 재분류했다(§13.2·13.3-2).
> 3. CoreGuard는 원본 예외가 아니라 원본 불변 + 실험 사본 분리로 진행한다. 독립 평가(Phase 5 설계)는 Phase 0에서 사전 등록한다(§13.5).
> 4. G4는 보류하고 OFF를 기준선으로 둔다(§13.3a).
> 5. #4 원목록 58건을 확보했다(§13.4).
> 6. 결정 사항을 승인 결과로 갱신하고 커밋 기록을 실제와 맞췄다(§13.7).

### 13.1 이슈 역할 분담 (이슈 본문 정의 수용)

| 이슈 | 책임 | 이 계획에서의 위치 |
|---|---|---|
| #1 | 증적 검증·재현 신뢰성 | §12(완료: G0). 새 지적 없음 |
| #2 | 탐색(발견) 능력: stateful fuzzing, fault injection | §12.6(G1~G5 수행). §13.4에서 #4 코퍼스로 평가 확장 |
| #5 | Phase 5 v2 판정기의 실패-닫힘(fail-closed) 보강 | **§13.3: 최우선 v2.1** |
| #4 | 2016–2026 결함 계보: 원문·패치·재현 상태 검증, ground-truth·hold-out 공급 | §13.4 |
| #3 | 방어(CoreGuard): 불변조건 강제·실패 원자성·격리와 그 효과 평가 | §13.5 |

### 13.2 #5 사실 확인 (현행 코드, 이력 재작성 후 HEAD `2288d8c`)

> 아래 "판정"은 **판정 코드의 결함이 타당한가**만 다룬다. 기존 실험 결과가 실제로 틀렸는지는 별도 표(기보고 결과 영향 점검)에서 증적으로 확인하며, 확인 전에는 "영향 미확인"으로 둔다.

| # | 지적 | 확인 결과 | 판정(코드 결함) |
|---|---|---|---|
| 1 | replay differential의 거짓 `extinct` | `sig_of()`는 시그니처 목록만 반환한다(`lifecycle-explore.py:854-859`). `extinct=target not in sigs`(`:887`)라서 수정 버전 서버가 기동하지 않아도 True가 된다 | 수용(P0) |
| 2 | FlowFusion 브리지의 거짓 `clean` | `run_program()`은 예외를 `harness_error` 단계로 남긴다(`flowfusion-bridge.py:179`). `classify()`(`:196`)는 이를 검사하지 않고, generator의 `returncode`도 미검사다(`:212`) | 수용(P0) |
| 3 | G3 재발견이 단계와 무관한 함수명 히트로 성립 | `hit = any(func in sig for s in steps)`(`explore-report.py:136`). `producer_landed`는 failure_sites가 비어 있지 않은지만, consumer는 단계 기록이 있는지만 본다(`:146`) | 수용(P1) |
| 4 | ground-truth 차단 지점이 ASAN 부재에 의존 | P16·P17 라벨은 이미 `consumption_absent`로 중립화했다(§10.11). P15의 `delivery_blocked`는 여전히 "OOM 없음 + 스크립트 도달"에서 추론한 것이다 | 부분 수용(관측·추론·검증 칼럼 분리) |
| 5 | 배치 러너의 실패 전파 | `explore-g34.sh`·`explore-g5.sh`는 `set -u`만 쓰고, 개별 rc를 출력만 한 채 최종 rc에 반영하지 않는다 | 수용(P1) |
| 6 | sancov 수집 실패와 "새 edge 0건"을 구분하지 않음 | `read_sancov()`가 glob 파일 수를 반환한다(`lifecycle-explore.py:318`). 매직 불일치나 부재도 빈 집합으로 처리된다 | 수용(P1) |
| 7 | readiness·PID 귀속의 fail-open | 아무 `HTTPError`나 ready로 처리한다(`:427`). PID가 없으면 귀속 검사를 생략한다(`:670`) | 수용(P1) |
| 8 | G5 통과 조건이 불충분 | `passed`는 SAPI 3종 + 중단 없음 + 하네스 오류 0만 요구한다(`explore-report.py:194`). 유효 실행 수·대상 도달 여부는 보지 않는다 | 수용(P2) |
| 9 | 차등 트리아지의 오분류 | `fixed_k`가 없어도 이후 분기로 진행한다. 수정 버전의 **다른** ASAN 시그니처는 경고하지 않는다(`differential-triage.py:85`). `carried`만 보고 `reset_inside_startup`으로 판정한다(`:93`). 종료 시점 NULL만으로 `residue_not_formed`라 부른다(`:108`) | 수용(P0) |
| 10 | 커버리지 맵의 근접 줄 = 도달 혼동 | 후보 줄 +6줄 창으로 판정한다(`coverage-map.py:120`). symbolizer·nm의 rc와 출력 수, 바이너리 동일성은 미검사다 | 수용(P1) |
| 11 | 메커니즘 정정의 근거 수준, G4 해석 범위 | §10.11의 "잔류 미생성"은 종료 시점 관측에 패치 소스 추론을 결합한 것이다. G4는 "이 문법·예산에서 우위가 입증되지 않음"이지 상태 피드백 일반의 무효가 아니다 | 수용(문서) |

**기보고 결과 영향 점검(증적 기반, 이번 반영 중 수행):**

| 대상 | 점검 | 결과(실제 영향) |
|---|---|---|
| FlowFusion "100/100 clean"(§10.10) | 프로그램별 `php-error.log`와 관측된 요청 시작(step 0~3) | **91** 정상 완료(요청 0 = 200 + 소비자 3단계 관측) / **4** 실행 중 fatal(500: final 메서드 재정의, 상수식, 미정의 인터페이스, `__debugInfo` 반환형) + 소비자 3단계 관측 — **유효한 탐색 사례** / **4** 생성 프로그램 문법 오류(`Parse error`, 500) + 소비자 3단계 관측 — 수명주기 실행은 유효하나 융합 프로그램 실행으로는 무효 / **1** 요청 0 장기 실행(`usleep` 루프)이 단일 프로세스 서버를 점유해 소비자 미실행(`consumer_incomplete`, 실제 무효). → "100/100 clean"은 철회한다. 수명주기 관측 완료는 **99/100**, 융합 프로그램 정상 실행(파싱 성공) 기준은 **95/99**이며, 둘 다 메모리 오류·잔류 0이다. 앞선 개정의 "≤91"도 HTTP 500을 일괄 무효로 본 과잉 정정이라 철회한다. **실제 결과 오류: 1건(prog 22)을 clean으로 센 것** |
| 1f differential 2건(§10.9) | 수정 버전 단계 실행 여부 | 두 건 모두 8.4.27에서 모든 단계가 실행되고 응답을 받았다(`runtime_oom 500 → parse_oom 200`, `session 200 → parse_oom 500 → upload_cookie 200`). **실제 결과 오류 없음 — 결론 유지.** 코드 결함(#5-1)은 수정한다 |
| 차등 트리아지 6건(§10.11) | 수정 버전 단계 누락 여부 | 누락 0건이므로 판정은 도달 상태에서 내려졌다. **판정 결과는 유지**하되, `residue_not_formed`라는 **명칭이 메커니즘을 과대 귀속**하므로 관측명 `absent_at_observed_shutdown`과 추론명을 분리한다(#5-9·11) |
| G3·G5 `passed` | 판정식 | 게이트 산식의 결함(#5-3·8)이 확인됐다. 실제 결과가 틀렸는지는 **영향 미확인**이며, v2.1 판정기로 재산출해 확인한다. 그 전까지 §12.6.6의 G3·G5 "통과"는 **잠정**이다 |

### 13.3 v2.1 작업 계획 — #5 실패-닫힘(fail-closed) 보강 (최우선)

원칙(`docs/lab-engineering-rules.md` R1·R2·R5·R6 적용):
- 실행 실패·미도달·관측기 실패·귀속 불명은 결코 성공·clean·extinct로 집계하지 않는다.
- 결과 어휘에 `harness_failed | not_reached | inconclusive | attribution_unknown`을 공통으로 둔다.
- 모든 수정에는 **의도적 실패 주입 픽스처**를 함께 둔다.

| 우선 | 항목(#5 번호) | 작업 | 완료 기준(픽스처) |
|---|---|---|---|
| P0 | 1 replay | `sig_of()`가 `harness_error`·서버 기동·단계 도달·생산자 착지·소비자 실행·ASAN 수집 상태를 함께 반환한다. 결과는 `reproduced / extinct_at_verified_block_point / not_reached / inconclusive / harness_failed`로 나눈다 | 수정 버전 바이너리 없음, 기동 실패, 소비자 미실행, 관측기 실패 → `extinct=false` + 비정상 종료 코드 |
| P0 | 2 FlowFusion | **HTTP 상태 코드가 아니라 로그·관측 근거**로 분류한다. 세 축으로 나눈다. ① 생성: `not_generated`(generator rc≠0, 생성 0건, `--FILE--` 없음). ② 요청 0: `server_start_failed` / `request0_not_executed`(step 0 startup 미관측) / `program_compile_error`(PHP `Parse error`·컴파일 fatal: 융합 결과물 결함) / `program_runtime_fatal`(실행 중 fatal·uncaught·OOM: **유효한 탐색 사례**, 500이어도 유효) / `program_completed`. ③ 소비자: `consumer_incomplete`(3단계 중 미관측, 예: 장기 실행 요청이 서버 점유) / `consumers_observed`. 종합 판정 `clean`은 요청 0이 실행됐고(②가 compile_error·runtime_fatal·completed 중 하나), 소비자 3단계가 관측됐으며, 메모리 오류·잔류가 0인 경우에만 붙인다. 분모는 "수명주기 관측 완료"와 "융합 프로그램 정상 실행(컴파일 성공)"을 별도로 보고한다. 장기 실행 요청에는 요청 0 타임아웃 후 `request0_timeout`을 기록한다 | 서버 미기동, step 0 미관측, 생성기 비정상 종료, 소비자 미관측 → `clean` 불가. 실행 중 fatal 500 → `program_runtime_fatal`로 유효 분모에 포함. Parse error 500 → `program_compile_error`로 따로 집계 |
| P0 | 9 triage | 양쪽의 harness·PID·단계 수·소비자 도달·관측기 유효성을 먼저 확인한다. 수정 버전의 **모든 ASAN**을 기록하고 `NOT_FIXED`와 `NEW_MEMORY_ERROR`를 구분한다. 칼럼은 `observed_state_at_shutdown` / `inferred_fix_mechanism` / `verified_block_point`로 나누고, verified는 해당 지점의 계측 이벤트(할당·해제·리셋 브레이크포인트)가 있을 때만 붙인다 | 수정 버전 소비자 생략, 기동 실패, 다른 ASAN, 양쪽 하네스 실패, "종료 시점 NULL이지만 해제 경로 불명" → 거짓 성공 불가. 이후 양성 5종·음성 1종 재산출 |
| P1 | 3 G3 인과 | 재발견 = 생산자 실패 지점(경로별 기대 위치) 확인 → 동일 워커·pid → 소비자 단계 실행 → **그 단계의** ASAN 시그니처. 함수명 단독 히트는 `signature_only`로 따로 기록한다. 게이트 `passed`는 경로별 재발견률과 분리해 보고하고, "P16 또는 P17 중 1건 허용" 기준은 계획 문구 그대로 유지한다 | 단계가 섞인 ASAN, 생산자 미착지, 다른 pid → `rediscovered=false` |
| P1 | 4 ground-truth | `observed_outcome` / `inferred_block_mechanism` / `verified_block_point` 칼럼을 분리한다. 음성 대조군은 정상 요청, 소비자 미도달, 관측기 미작동, 다른 지점 OOM | 각 대조군이 `verified`로 판정되지 않음 |
| P1 | 7 readiness·귀속 | 준비 판정을 분리한다. 워밍업 health 200을 단언하고(R1), 주입 fault로 인한 500은 `fault_expected`로 기록한다. PID를 얻지 못하면 `attribution_unknown`으로 하고 `memory_error_confirmed` 대신 쓴다 | 500만 나오는 readiness, PID 미관측 + ASAN 파일 존재 |
| P1 | 5 배치 | 개별 rc·`aborted`·`harness_errors`를 모아 배치 최종 rc와 `batch.json`에 반영한다 | rc=3 하위 실행, summary 누락, 실행 0건 → 배치 실패 |
| P1 | 6 sancov | `coverage_not_collected / coverage_invalid / coverage_valid_no_new_edges`로 나눈다. 유효 파일 수를 센다. 커버리지 양성 대조군(health 1회의 edge 수 > 0)이 확인되기 전에는 code-edge 평가를 하지 않는다 | 잘못된 magic, 누락, 0바이트, 정상 파일 |
| P1 | 10 coverage map | `nearby_source_coverage / exact_site_covered / fault_path_reached`(실행 증거 필요)로 나눈다. symbolizer·nm의 rc·출력 수·미해석 비율을 검사한다. 바이너리 SHA-256·버전·flavor·run_id를 묶는다. §10.11의 14/44 등은 "근접 소스 줄"로 표기를 정정한다 | 후보 줄 실행, 주변 줄만 실행, 심볼 실패, 다른 바이너리 |
| P2 | 8 G5 | `valid_executions`, `target_reached`, `worker_identity_checked`, `observation_available`를 추가한다. "3종 환경 구성 성공"과 "기존 결함 경로 비교 검증 성공"을 별도 게이트로 둔다 | 실행 0건·미도달 프로파일 → 실패 |
| P2 | 11 문서 | §10.9~10.11의 `100/100 clean`, `G3 passed`, `G5 passed`, `14/44`, `residue_not_formed` 표기를 분모·범위·`validated / incomplete / inferred` 상태와 함께 재기재한다. G4 해석 범위도 명시한다 | 문서가 재산출 수치와 일치 |

**v2.1 완료(Done):**
- 위 실패 주입 픽스처가 모두 기대한 `not_reached / inconclusive / harness_failed`를 반환한다.
- 양성 대조군(P15~P17, Bug S, Path B 교착)의 8.4.4 재현과 8.4.27 소멸이 유지된다.
- **같은 소스 SHA·환경·run_id 체계로 G3·G4·G5, FlowFusion, 트리아지를 재실행해 게이트를 재산출**한다. 그 전까지 해당 수치는 "잠정"이다.

### 13.3a G4 피드백 전략 — 보류, OFF를 기준선으로 (승인)

- 현재 피드백 ON은 기존 비교와 code-edge 추가 비교 모두에서 열세였다. 당분간 **무작위 생성(OFF)을 성능 기준선**으로 둔다. 모든 새 탐색 실험은 같은 예산의 OFF 대조를 동반한다.
- ON은 재설계 대상이다. 신호 후보는 code-edge 수가 아니라 다음 네 가지에 가중치를 두는 상태 피드백이다.
  - 요청 간 소유권 전이(carried 필드의 종류·조합)
  - 오류 복구 경로(fatal 뒤 정상 응답, 지연 OOM 경로)
  - 객체 재진입(소멸자·콜백 중 상태 변경)
  - 예상치 못한 GC 상태 변화(`gc_protect`·GC 활성 여부)
- 재설계 ON은 #4 hold-out이 아니라 **별도 튜닝 세트**로만 조정한다. hold-out은 평가에만 쓴다(§13.4 H3·§13.5 사전 등록).

### 13.4 #4 Historical Corpus — 계획 반영

**목표:** 2016–2026 공개 기록에서 반복된 실패 패턴을 검증된 ground-truth·hold-out으로 바꿔 #2(탐색)와 #3(방어)의 평가 기반으로 쓴다. 공식 패치를 대체하지 않으며, 신규 결함은 책임 신고한다.

| 단계 | 작업 | 우리 스코프 결정 |
|---|---|---|
| H0 목록 확보 | 사용자가 제공한 원조사 문서 `docs/corpus/php-memory-safety-2016-2026.md`(원본 그대로, 58개 기록 표 + 계보·방어 제안 절)를 저장소에 넣었다 | **확보 완료.** 58건에는 수정 완료, 미검증 제보, 설계 논의가 섞여 있으므로 "검증된 취약점 58건"으로 다루지 않는다. 분류는 H1에서 한다. #5 수정과 **병행 가능**(승인) |
| H1 코퍼스 검증 | 건별 원문 URL·보고일·영향 버전·현재 상태·관련 PR/커밋·수정 버전을 확인한다. 분류 축은 `fixed / open / duplicate / unverified / design-discussion` × `crash / sanitizer-confirmed / exploitability-assessed` × 노출 조건(원격 요청 / 앱 콜백 / CLI·확장 전용). 같은 root cause, 유사 증상, 키워드 일치를 구분한다 | `docs/historical-corpus.md` + 기계 판독용 `linux/corpus/records.json`. bugs.php.net의 오래된 상태만으로 현재 취약을 단정하지 않는다 |
| H2 독립 재현 | 우선순위는 이슈 순서를 따른다: #79760, #10026, #12073, #24361, PR #22710 → 재진입 계열 #16726, #20018, PR #6903·#12805 → #76167, #14083, PR #14304. 수정 전 버전 / 공식 수정 버전 / 현재 HEAD를 분리해 PHPT·ASAN·GDB로 `reproduced / not_reproduced / not_reached`를 판정한다 | 빌드 비용이 크다(버전마다 ASAN 빌드). 기존 `build.sh` 흐름을 따르고, 원본 소스는 수정하지 않는다. 재현 실패를 안전 판정으로 쓰지 않는다. 판정기는 v2.1 이후의 fail-closed 버전만 쓴다 |
| H2.5 입력 생성 능력·실행 환경 확장 | 사례별로 **현재 탐색기 문법으로 도달할 수 있는가**를 먼저 판정한다: `reachable_now`(multipart·session·unserialize 10개 액션) / `needs_php_code`(GC·소멸자 재진입·에러 핸들러 등 사용자 코드가 필요) / `needs_extension`(SOAP·mbstring·EXIF·XML 등, 현재 ASAN 빌드는 `--disable-all` + session) / `needs_sapi`(FPM master 등) / `out_of_scope`. 필요한 확장을 담은 빌드 flavor와 PHP 코드 생성 액션(예: FlowFusion 브리지의 융합 프로그램을 시퀀스 단계로 쓰는 `fused_program` 액션)을 추가한다 | **hold-out 적용(H3) 전에 완료해야 한다.** 그렇지 않으면 탐색 실패와 단순 미도달을 구분할 수 없다. 미도달 사례는 탐색 실패로 세지 않고 `capability_gap`으로 보고한다 |
| H3 #2 연결 | 검증된 사례만 ground-truth로 받는다. **튜닝용과 독립 hold-out을 분리한다.** 원인별 회귀 세트: bailout·GC, OOM·부분 초기화, 재진입, 요청 수명 | G3의 약점(정답이 길이 2 쌍이라 문법 밀도로 재발견, §10.9)을 #4의 hold-out으로 재평가한다. 즉 G4의 "피드백 무효" 여부를 더 어려운 공간에서 다시 판단할 근거가 된다 |
| H4 #3 연결 | 패턴별 방어 가설을 `prevention / pre-dereference enforcement / detection / containment`로 분류한다. 공식 패치로 이미 해결된 것은 신규 효과로 세지 않는다 | §13.5 Phase 0·5의 입력 |

### 13.5 #3 PHP CoreGuard — 계획 반영

**목표:** 109618·109619에서 확인된 일반 불변조건 위반(부분 초기화 상태 소비, 요청 메모리 수명 후 전역 참조)에 대해 미발견 동류 결함을 사전 차단하거나 영향을 축소하는 보호 기능을 연구한다.

**성공 기준(승인):** 공식 패치가 이미 막은 경로(P15~P17 등)를 다시 막는 것은 성공으로 세지 않는다. **사전 등록한 독립 hold-out의 새로운 실패 경로에서 보호 효과를 입증**해야 한다(유효 요청 유지 + 잘못된 접근·상태 공개 이전 차단). 입증하지 못하면 `detect-only` 등으로 낮춰 분류한다.
- 하지 않는 것: 공식 패치 재구현, "모든 제로데이 방어" 주장.
- 안전 경계: 격리 랩, RCE 무기화 비목표, 신규 결함 상세 비공개.

| Phase | 작업 | 선행 조건·스코프 결정 |
|---|---|---|
| 0-평가 사전 등록 | **Phase 5 평가 설계를 지금 시작한다.** 보호 기능 구현 전에 독립 hold-out 사례 목록(#4 H1에서 검증된 사례 중 튜닝·개발에 쓰지 않을 것), 판정 기준(`prevented_before_invalid_access` 등), 측정 지표·반복 수·예산을 문서로 확정한다. 목록 해시를 포함해 **구현 커밋보다 먼저 커밋**한다. 이후 변경은 사유와 함께 별도 커밋으로만 한다 | 구현 후 hold-out을 고르면 무의식적으로 유리한 사례를 고를 수 있어서다. 공식 패치(8.4.27)가 이미 막은 경로는 "신규 보호 효과"의 분모에서 제외한다 |
| 0 기준선 | 실험군 3종을 분리한다: 8.4.4(취약) / 8.4.27(공식 수정; 필요 시 8.5.12) / 8.4.27 + CoreGuard. 공식 패치가 이미 막는 것과 잔존 구조적 공백을 소스 위치·조건으로 문서화한다. 현재 근거: §10.11 트리아지에서 8.4.27 소멸은 fallible 할당 + 지연 OOM이었고, 조기 리셋은 미실행 이중 방어였다. 모든 시험에 `mode=observe / enforce / disabled`, run_id, SHA, SAPI, pid, 소유 요청, 할당·해제 지점을 기록한다 | **#5 v2.1(fail-closed 오라클) 완료가 선행 조건**이다. #4의 H1이 공백 후보를 공급한다 |
| 1 Request Ownership Guard | ZendMM의 request/persistent 모델 위에 `request_epoch`·`allocation_owner`를 둔다. 등록된 전역(BG serialize/unserialize, PS id/mod_data, 일부 EG)의 접근 지점에 검사 훅을 둔다. `observe`로 정확도·오탐을 먼저 재고, 역참조 전에 거부할 수 있는 지점부터 `enforce`를 적용한다 | 수정 빌드는 승인됐다. §3.2의 원본 무결성 원칙은 예외 없이 유지하고 다음과 같이 분리한다: **공식 원본 소스**(`sources/php-*`)는 변경 금지 / **CoreGuard 실험 소스**는 별도 사본 또는 worktree(`ext/coreguard-src-8.4.27`) / **변경 내용**은 `linux/coreguard/*.patch`와 독립 커밋 / **빌드명**은 `8.4.27-coreguard` 등 별도 / **평가**는 공식 수정 버전과 CoreGuard 적용 버전을 대조. 등록되지 않은 raw pointer, 확장의 직접 `malloc`, JIT/FFI는 잔여 위험으로 보고한다 |
| 2 Failure-atomic | count-before-init 후보(fault-site-map·커버리지 맵 공백)에 `prepare → validate → commit`을 적용할 수 있는지 분석한다. 8.4.27의 지연 soft OOM과 차별화한다. 주입은 `ZEND_MM_MAX_ALLOCS`(사후 시작 한정, pre-RINIT은 별도 계측)를 쓴다 | 정상 API 의미 보존을 PHPT로 검증한다 |
| 3 Containment | `worker_integrity_state = clean / suspect / poisoned`. 위험한 정리 **이전**에 격리한다. 단순 OOM이 워커 재시작 DoS로 증폭되지 않는지 확인한다 | §10.10 관측과 연결: FPM에서는 파싱 fatal에 워커가 교체된다. 가용성 회귀 측정이 필수다 |
| 4 Allocator·HW | ZendMM 대 `USE_ZEND_ALLOC=0` + GWP-ASan·Scudo 비교. 샘플링 검출과 강제 차단의 보장 수준을 구분한다 | 낮은 우선순위. MTE·CHERI·샌드박스는 장기 과제 |
| 5 반증 가능한 평가 | Phase 0에서 사전 등록한 **튜닝에 쓰지 않은 hold-out**에서 `disabled / observe / enforce`를 동일 입력·동일 예산·독립 반복으로 대조한다. 결과 분류: `prevented_before_invalid_access / detected_only / worker_contained / not_reached / not_protected / test_failed`. PHPT·세션·업로드·JIT·3 SAPI 호환성과 req/s·p95·RSS·재시작률을 함께 잰다 | Go/No-Go는 이슈 §단계별 판정을 그대로 따른다 |

### 13.6 실행 순서

1. **#5 v2.1 P0**(1·2·9) + 픽스처 — 병행: **#4 H1(코퍼스 정리·출처 검증)**. H0은 완료
2. #5 P1(3·4·7 → 5·6 → 10)
3. #5 P2(8·11)
4. **재산출:** 같은 SHA·run_id 체계로 G3·G4·G5·FlowFusion·트리아지를 재실행하고(정상 실행 분모와 인과 재검증), §12.6.6과 findings를 갱신한다
5. #4 H2(재현) → **H2.5(입력 생성 능력·실행 환경 확장)** → **#3 Phase 0-평가 사전 등록(hold-out 고정)**
6. #4 H3(#2 hold-out 재평가 — OFF 기준선 대비, 재설계 ON은 튜닝 세트로만 조정)
7. #3 Phase 0 기준선 → Phase 1(observe) → 2 → 3 → 5(사전 등록 hold-out으로 평가). Phase 4는 병행 저우선

커밋·푸시는 요청 단위로 판단한다(R10).

각 단계 종료 시 §13 표를 갱신한다. 결과는 findings의 새 절(§11 이후 "Phase 6 — Corpus·CoreGuard")에 v2와 구분해 기록한다.

### 13.7 결정 사항 (2026-10-23 사용자 승인)

| 결정 사항 | 결정 |
|---|---|
| #5 v2.1 우선 수행 | **승인** — P0 오류부터 수정 |
| G3·G4·G5 재산출 | **승인** — 정상 실행 분모와 인과관계 재검증 |
| G4 피드백 전략 | **보류**, OFF를 기준선으로 유지(§13.3a) |
| CoreGuard 수정 빌드 | **승인**, 원본 불변·실험 사본 분리(원본 예외 신설 없음, §13.5) |
| #4 원목록 | **58건 파일 확보**, H0 완료 → H1 진행 |
| #4와 #5 병행 | **승인** — #4 자료 정리·출처 검증은 #5 수정과 병행 |
| FlowFusion HTTP 500 판정·CoreGuard 독립 검증 설계 | §13 실행 전 정정 요구 → 본 개정으로 반영(§13.2·13.3-2·13.5) |

**커밋 기록 정정:** 이 절의 초판에는 "이번 계획 반영분은 커밋하지 않고 대기한다"고 적혀 있었다. 실제로는 사용자 승인 후 `446b1c9`(Plan 13)로 커밋해 `main`에 push했다. 본 개정도 같은 방식(요청 단위, R10)으로 처리한다.
