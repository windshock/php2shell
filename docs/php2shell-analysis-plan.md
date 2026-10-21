# PHP2Shell 취약점 확인·분석·E2E 테스트 계획 (패치 전)

> 작성: 2026-10-21 21:30 KST · 대상: PHP 8.4.4 / 8.5.4 로컬 검증 랩 · 상태: 공식 패치(23:00 KST 예정) 공개 전

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

## 7. Phase 4 — 공식 패치 공개 후 (23:00 KST 이후, 후속 작업)

1. php.net 보안 공지·GitHub 신규 태그 확인 → CVE별 영향/수정 버전·공격 조건 확정.
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
| FlowFusion (USENIX'25) | PHPT 입력 활용, 설정 변형, 메모리 오류 수집, 실패 입력 보존·축소 | `linux/fuzz-profile.sh`(예정) | 미실행 | 전체 파이프라인 |
| PHP 공식 Fuzzer SAPI | `--enable-fuzzer` 빌드, 기존 Corpus | `linux/build.sh` 확장(예정) | 미실행 | 빌드·Corpus |
| Calif MAD Bugs / php-unserialize-audit | `Serializable` 재진입, `__wakeup/__destruct`, `var_hash` 수명, 세션 디코더 차이 | 정적 체크리스트(S9, 문서) | 문서만 | 자동 스캔 |
| ZendDiff | 내부 상태 프로빙·차등 비교, 비결정성 제거 | `linux/gdb-probe.py`, `linux/http-compare.py` | **실행 검증** | JIT 비교 |
| ATROPOS / PHUZZ | 상태 유지 HTTP 시퀀스, 스냅샷·복원, 오류 수집 | `linux/probe.py` P4(교차 요청) | **실행 검증** | 커버리지 계측 |
| WAFFLED | 원문 바이트 보존, WAF vs PHP 파싱 비교, 오탐/누락 평가 | `linux/waf-lab.py`(예정) | 미실행 | 로컬 WAF 구성 |
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
| HTTP 입력만으로 OOM(Arm 단계) | 미실시 | P1 후속: 로컬 세션 위조 없이 body 크기만으로 OOM 도달 여부 측정 |
| Zend vs 계측 할당기 구분 | 부분 완료 | zend 모드에서 decode OOM로 다른 지점임을 확인(§2.7c) |

## 10. 산출물 목록

1. `docs/php2shell-analysis-plan.md` — 이 문서.
2. `linux/probe.py` (+ `linux-probe.cmd`) — HTTP E2E 프로브 하네스(P1~P7).
3. `linux/gdb-probe.py` (+ `linux-gdb.cmd`) — 요청 수명·직렬화 상태 계측 하네스(P8).
4. `linux/http-compare.py` — 동일 입력 HTTP 전후 비교 도구(판정 어휘 포함).
5. `linux/poc-bgserialize.py` — L0 트리거 PoC 러너(재현율 측정, 익스플로잇 아님).
6. `linux/build-apache.sh`, `linux/apache-lab.sh`, `linux/apache-poc-matrix.sh` — Apache mod_php 랩(빌드·기동·재현율).
7. `linux/verify-evidence.py` — 증적 자동 감사(회차별 ASAN·PID, GDB 인덱스, 매니페스트).
8. `linux/gdb-unserialize.py` — `BG(unserialize)`(Bug U) 상태 계측·재현 하네스.
5. `var/linux-evidence/evidence/probe-*/`, `probe-gdb-*/` — 프로브 실행 증적.
6. `var/linux-evidence/evidence-manifest.sha256` — 증적 해시 매니페스트.
7. `docs/php2shell-analysis-findings.md` — 정적·동적 분석 결과 및 주장별 판정표.
