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
| #1-P0: 매니페스트 검증기가 `hash *file`(바이너리 표기) 행을 무시하고 `checked==0`도 통과 | **확인** — `check_manifest()` 정규식은 두-공백 형식만 매칭, 미해석 행 `continue`, 0건도 `passed`. 단 현행 10/22·10/23 매니페스트에는 `*` 행 **0건**(Git Bash sha256sum 텍스트 형식) → 실제 무결성 훼손은 없음. 강화는 방어 조치로 정당 | 수용 |
| #1-P1: 퍼저 "정상 progress 시드" 직렬화 형식 파손 | **확인** — `bytes_processed` 14≠15, `full_path` 8≠9, 외부 `a:5`≠실제 3원소. 정상 시드가 실제로는 비정상 입력이었음 | 수용 |
| #2: `ZEND_MM_MAX_ALLOCS`가 `php_hash_environment()` 이후에만 설정돼 pre-RINIT 파싱 실패 지점을 못 덮음 | **확인** — 8.4.27 main.c:1906(파싱) → :1914(환경변수 훅). 요청별로도 훅은 해당 요청 파싱 이후 | 수용 — Stage 2 제약으로 반영 |
| #1: 러너 `|| true` 실패 마스킹, poc-pathb 로그 전체 판독, poc-pathc 판정 미반영, gdb-state-diff 스코프 과대 표기 | **확인** — 모두 코드상 정확 | 수용 |

### 12.2 Issue #1 작업 계획 — "Phase 5 v1.1 신뢰성 보강" (우선 실행)

| 우선순위 | 작업 | 대상 | 완료 기준 |
|---|---|---|---|
| P0 | `check_manifest()` 강화 — `hash  file`/`hash *file` 양 형식, 미해석 행 = 실패, `checked==0` = 실패, 항목/성공/누락/불일치 수 출력, 테스트 픽스처(정상·바이너리·오류행·0건·불일치) 추가 | `linux/verify-evidence.py` | 이슈 #1 완료기준 1 — 0건 검사 통과 불가 |
| P1 | P15 판정 강화 — ① `gdb-patha.py`: 카운터 증가 이후 미초기화 Bucket 상태 관측 명령 추가 ② `poc-patha.py`: `fatal_and_teardown_memory_error`를 "지정 key-alloc 사이트 + 해당 teardown 소비" 증거 결합으로 세분화(단순 fatal·타 지점 ASAN은 별도 판정) ③ 회차 PID·실행 ID·ASAN/SEGV 연결, 카운터 이전 착지 대조군 자동 확인 | `linux/gdb-patha.py`, `linux/poc-patha.py` | 완료기준 2 — 오진이 `reproduced`로 집계되지 않음 |
| P1 | 퍼저 정비 — 시드 3곳 형식 수정(정상 시드는 통과하는 직렬화로, 비정상은 별도 시드), 정상 시드 `unserialize()` positive control, 사전 생성 실패·exit code·timeout 상태 분리, **§11.1 "야간 3회" ↔ 실제 25분×3 불일치 정정**, `php-fuzz-unserialize`가 multipart·요청 간 수명을 직접 커버하지 않는다는 한계 명시 | `linux/fuzz-phase5.sh`, §11.1·findings §9.4 | 완료기준 3 |
| P1/P2 | 러너 신뢰성 — 매트릭스 `|| true` 마스킹 제거(기대 재현/필수 증적 누락 시 non-zero), `poc-pathb.py` OOM 판정을 요청 A 이후 로그 구간으로, `poc-pathc.py` `fatal_in_unserialize`를 성공 판정에 반영 + A 생산자/B 소비자 동일 실행 귀속, `gdb-state-diff.py` 스코프를 "등록된 BG/PS/url_scanner 상태의 요청 경계 diff"로 명시(전역 무탐색 아님), `docs/README.md`·exec summary 기준 시점 갱신 | 해당 러너·문서 | 완료기준 4 — 하위 실패가 상위 종료 코드·요약에 전파 |

### 12.3 Issue #2 반영 — Phase 5 v2 계획 (탐색 고도화, #1 완료 후 본격 실행)

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
