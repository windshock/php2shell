# #6 P0 — invariant_signals 계층 사전등록 (2026-10-24, 계획 §15.1, 이슈 #6)

> 실행 전 동결. P1(shadow extractor)은 이 문서 커밋 후에만 착수한다. 관측 원천은 **기존 STATE/EVENT 출력뿐**(새 gdb 중단점 금지 — 검토 주의 ④, 실행 비용 대부분이 gdb 관측). 모든 시그널은 단계(`stage`)와 신뢰도(`confidence`)로 분리 보고되고, 아래 무보상 조건의 상태는 절대 보상·성공으로 세지 않는다.

## 1. 부류 정의

### I-GC — 잡힌 bailout 뒤 GC 보호 복구

불변조건: 잡힌 bailout 이후 보호가 해소되지 않은 채 사용자 코드 실행이 이어지지 않는다.

> **v2 개정(2026-10-25 00:04 리뷰, 사유 기록)**: v1 preconditions("bailout EVENT + 스텝 진행")은 **종료형 fatal도 모두 만족**했다 — `_zend_bailout()`은 종료형에서도 항상 `gc_protect(1)`을 건다(`Zend/zend.c:1262`)且 startup 관측 중단점이 `php_request_startup` **진입**이라 `zend_activate()`의 `gc_reset()`(`zend_gc.c:538`)보다 **먼저** 찍히므로, 종료형 fatal 뒤 다음 startup의 `gc_protected=1`은 **정상 엔진 상태**다. 실측(2×2 전 exec, 같은 pid): bailout EVENT 스텝 → 다음 startup 보호 **274/274(100%)**, 무bailout → 0/1,415 — v1 progress는 판별 정보 0(autology). v1 shadow 실행 `invariant-shadow-20261024T145621`은 **"v1 정의 결과"로 표지·보존**한다. 개정 선택: **(b) preconditions를 "잡힌 bailout 뒤 정상 반환"으로 좁힘**(기존 `ended_normally` 판정 재사용 — 관측점 추가 불필요). **(a) gc_reset 이후 관측**은 새 gdb 중단점을 요구해 shadow 원칙(기존 출력만)과 충돌 — P2에서 비용 측정 후 재검토. > **구조적 기대값(동결, v2 실측으로 정밀화)**: **기본 액션 문법 캠페인(2×2 F·H 전 셀)에서 I-GC 진전은 0**(실측 확인) — 3군 비교에서 이 축의 무효과는 설계다. **융합 풀 캠페인이 I-GC v2의 신호원**이다: h2.5 문법 런(h3 T232756, 8.4.27) 3런에서 정상 완주한 잡힌 bailout(주로 fused 프로그램의 오류 포획 후 `LAB-FUSED-END`) 40건 — preconditions=progress=candidate.

| stage | 정의(동결 v2) | 관측(동결 v2) |
|---|---|---|
| `preconditions` | 이 요청에서 bailout이 잡혔고(= `_zend_bailout` EVENT) **정상 반환**(`ended_normally` = `completed` 또는 failure_sites 비음 — 기존 G 키 판정 재사용) | EVENT 로그 + steps |
| `progress` | 보호가 **요청 경계를 넘어** 잔류 — 같은 워커(pid 동일)의 **다음 요청 startup STATE에서 `gc_protected=1`**. 정상 반환 뒤에도 남아 있다는 것이 v2에서 의미를 갖는다(종료형은 preconditions에서 이미 배제) | observer STATE(다음 요청 startup) |
| `candidate` | preconditions ∧ progress ∧ 기존 키가 같은 사실에 보상을 주지 않음(§2 매핑 v2: I-GC는 G와 **같은 전제 부류, 다른 경계**(자기 shutdown vs 다음 startup) — 스텝 양쪽 발화 가능, 승격 시 동일 스텝 적립 금지) | 위 둘 + 매핑 확인 |
| `confirmed` | candidate가 **결정적 재실행**(replay)에서 재현(새 프로세스에서 경계 횡단 재관측) 또는 같은 워커의 후속 ASAN 오류로 속성 상승 | replay/validate 기계 + ASAN 귀속 |
| (분류) | `anomaly_no_bailout_protected`: bailout EVENT 없이 다음 startup이 보호된 경계 — EVENT 누락(관측 실패) 또는 shutdown 중 bailout 후보로 분리 기록(2×2 실측 0건, 리뷰 관측 22건은 wider 데이터) | observer 대조 |

### I-REQ — 요청 경계 소유 상태

불변조건: 요청 소유 상태는 다음 요청 startup에 보이지 않는다.

| stage | 정의(동결) | 관측 |
|---|---|---|
| `preconditions` | 직전 요청이 **비정상 종료**(failure_sites 비음, 즉 fatal/bailout 경유) | steps.failure_sites |
| `progress` | 같은 워커 다음 요청 startup STATE의 **요청 소유 필드**(ser/unser 레벨>0, ps_id/ps_mod/ps_session_vars 비null, url_hosts>0)에 잔류(fresh/carried) | observer STATE + normalize_state |
| `candidate` | preconditions ∧ progress(정상 종료 후 잔류는 후보 아님 — 정상 정리와의 구분이 정의의 핵심) | 〃 |
| `confirmed` | 재실행 재현 + (상승 시) 후속 요청의 소비 관측(디코드 fatal 등, CVE 패턴) | replay + 후속 steps |

## 2. 기존 키와의 매핑 — 이중 보상 방지 (검토 주의 ①)

| 기존 키 | 의미 | I-*과의 관계(동결) |
|---|---|---|
| `G:<act>\|<gc>` | 정상 종료 요청의 shutdown GC 이상(또는 protected 외 odd) | **분리** — G는 요청 내 shutdown 관측, I-GC는 **요청 경계 횡단**(다음 startup)만. 같은 스텝에 둘 다 발화 가능하나 다른 사실 |
| `G:<act>\|oom_while_gc_protected` | 보호 중 delayed OOM(비 shutdown) — R49 부류 | I-GC의 `progress` 관측 원천 **중 하나**(재개 증거의 한 형태)로 재사용 — candidate 산출 시 이 키에는 추가 보상 없음 |
| `R:<act>\|<gc>` | failure 후 2xx 응답+생존(회복) | I-GC preconditions의 보조 지표(재개 증거) — 재사용, 중복 보상 없음 |
| `S:`/`H:` | 경계 상태 변화 전반 | I-REQ candidate는 그 **하위집합**(비정상 종료 후 소유 필드 잔류) — shadow는 겹침 통계를 보고하고, 피드백 승격 시 해당 스텝의 I-REQ가 H 보상을 **대체**(가산 아님, 스텝·불변조건당 최대 1보상) |

## 3. 출력 필드 (동결)

`invariant_id`(I-GC/I-REQ), `stage`(preconditions/progress/candidate/confirmed), `preconditions_observed`(사실 리스트), `observer_status`(gdb_ok/gdb_missing/observer_error), `evidence_ids`(run·exec·step·event id), `same_worker`(pid 일치 여부 — 경계 횡단의 전제), `confidence ∈ {progress, candidate, confirmed, unknown}`.

## 4. 무보상·비성공 조건 (동결)

- `harness_failed`(프로세스 기동 실패·관측기 오류), `not_reached`(preconditions 미충족), `inconclusive`(경계 관측 결측/partial) — **보상 0**, confidence=unknown 기록.
- **ASAN 부재, 종료형 fatal, 주소 재등장(carried의 재등장)은 성공 판정이 아니다.** carried 표시가 포함된 I-REQ progress는 #7의 가짜 동일성 격리와 같은 주소 재사용 주의를 달아 기록한다.

## 5. 생성기 게이트 (검토 주의 ③, P2 사전등록에 인용)

- 3군 비교(OFF·state·invariant)의 생성기는 **기본 요청(액션) 문법으로 고정**(2×2 H축과 동일 — 그 정정 참조). 부류 문법(`payload-grammar.py`)은 예산 여유 시 2차 브랜치 — 단 I-GC 진전이 부류 문법에서 구조적으로 쉬웠다는 기록(§11.14: CLI 205/300, H3 G 3/3; FlowFusion 풀에서 0 — §11.6)을 해석에 명시하고, 부류 문법의 hold-out 설계 지식(§11.14) 때문에 그 결과는 독립 재발견 근거로 쓰지 않는다.
- 처리량 하한: shadow/피드백 모두 해당 런 `execs` 감소 ≤25%(2×2 동결 규칙 인용).

## 6. P1 진입 게이트

이 문서의 커밋 = 동결. P1 shadow extractor(`observe()`·`verdicts.integrity()` 위 별도 계층, 선택 미반영)는 (a) 본 문서 필드·단계 그대로 출력 (b) 기존 증적(2×2·h3 런)에 대한 오프라인 계산으로 **겹침 통계(§2)와 단계 분포**를 먼저 보고한 뒤 코드에 반영한다.
