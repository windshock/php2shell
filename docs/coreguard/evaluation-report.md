# CoreGuard Phase 5 — 평가 보고 (2026-10-24)

> 사전 등록 `evaluation-preregistration.md` v1(hold-out 고정, 목록 SHA-256 `acf42610…`)과 v1.1(CLI 판정 매핑, 사례별 1회 평가)에 따른 결과다. 근거 수치와 증적 경로는 findings §11.8~§11.12에 있다.

## 1. 평가 질문에 대한 답

> 공식 수정(8.4.27)이 막지 않은 실패 경로에서, 개발에 쓰지 않은 hold-out에 대해, **유효 요청을 유지하면서** 잘못된 접근 이전에 차단했는가?

**아니다. `prevented_before_invalid_access`는 hold-out 3건 × 3모드 × 3회에서 0건이다.**

| hold-out | 패턴 | disabled | observe | enforce |
|---|---|---|---|---|
| R23 GH-10026 | bailout 뒤 GC 보호 잔류 | `not_protected` ×3 | `detected_only` ×3 | `worker_contained` ×3 |
| R46 PR #22710 | 정리 중 소멸자 bailout → 이중 정리 | `not_protected` ×3 | `detected_only` ×3 | `worker_contained` ×3(ASAN 0, rc 70) |
| R51 GH-24455 | 소멸자 재진입(lazy object reset) | `not_protected` ×3 | `not_protected` ×3 | `not_protected` ×3 |

- enforce는 R23·R46에서 피해가 나기 **전에** 작업 단위를 끝냈다(R23: GC 정지 전, R46: 세션 인코더 진입 전). 그러나 그 요청은 잃는다. v1.1 규칙에 따라 성공(`prevented`)이 아니라 `worker_contained`다.
- R51은 bailout이 없는 재진입이라 어떤 가드도 개입하지 않았다.

## 2. 독립성에 대한 정직한 평가

- R23은 튜닝 사례 R49와 같은 계열이다(사전 등록이 의도한 분리). R23 결과는 "같은 부류의 다른 진입점(opcache → soap)으로 일반화된다"는 근거일 뿐이다.
- R46은 원인과 수정 PR의 접근을 개발 전부터 알고 있었다. Phase 3 부류 정의("소멸자 안 bailout")도 이 지식에서 출발했다. 따라서 R46 결과는 **독립적인 입증이 아니다.** 입증하려면 개발에 관여하지 않은 새 hold-out(예: #2 탐색이 찾은 미공개 사례, D1 절차 후)이 필요하다.
- 결론적으로 이 평가가 보인 것은 "알려진 부류에 대한 탐지(observe)와, 요청을 희생하는 격리(enforce)가 작동한다"까지다.

## 3. Phase별 Go/No-Go

| Phase | 내용 | 판정 | 근거 |
|---|---|---|---|
| 0 | 기준선·사전 등록 | 완료 | `phase0-baseline.md`, B 성능·PHPT 기준선 |
| 1 | 요청 소유권(잔류 탐지, observe 전용) | **detect-only, 성공 주장 불가** | hold-out 없음(선언된 공백). 양성 대조 4/4. 8.4.27 탐색·PHPT 이벤트 0(공식 조기 리셋이 지울 잔류가 생기지 않음) |
| 2 | 할당 실패 원자성 | **No-Go(중복)** | 할당 실패 주입 10개 부류에서 모든 실패가 지연 OOM fatal로 끝남. 메모리 오류 0. 공식 수정과 중복이라 구현하지 않음 |
| 2b | 잡힌 bailout 뒤 GC 보호 | observe **Go(detect-only)** / enforce **No-Go** | observe: PHPT 회귀 0, 성능 노이즈 안, R23 탐지 3/3. enforce: PHPT 회귀 19(SOAP 정상 흐름 종료) |
| 3 | 소멸자 bailout 격리 | observe **Go(detect-only)** / enforce **조건부(가용성 대가)** | observe: 회귀 0, R46 탐지 3/3. enforce: 추가 PHPT 회귀 0, R46 피해 전 종료 3/3, 정상 부하에서 워커 종료 0. 단 소멸자 안의 OOM도 종료를 일으켜 재시작 유도가 가능하다(설계 §5) |
| 4 | 할당기·HW | 낮은 우선순위 유지 | 이중 해제(R55)만 결정적으로 검출. R41·R42는 검출 없음. GWP-ASan 추가 이득 없음 |
| 5 | 반증 가능한 평가 | 이 문서 | `prevented` 0 |

## 4. 측정하지 못한 것 (평가 범위의 공백)

- hold-out 평가는 CLI에서만 했다. Apache(mod_php)·FPM에서의 hold-out 동작과 FPM 워커 교체 뒤의 다음 요청 처리는 재지 않았다. `worker_contained`의 "다음 요청은 새 워커에서 정상"은 CLI에서 확인할 수 없다.
- JIT 빌드와의 호환성은 시험하지 않았다.
- PHPT는 7개 디렉터리(7,922건)다. 전체 테스트 스위트가 아니다.
- 성능은 단일 호스트(WSL2, 6코어)에서 잰 상대값이다. 측정 간 변동이 크다(같은 B 빌드의 health가 7.7k~9.5k req/s).

## 5. 다음 단계 제안

1. hold-out v2: 개발에 관여하지 않은 사례를 확보한다. #2 탐색에서 부류를 겨냥한 입력 생성(H2.5 남은 과제)을 하고, 새 메모리 오류는 D1 절차를 먼저 밟는다.
2. FPM에서 enforce의 가용성 비용을 잰다. 소멸자 안 OOM을 반복 유발했을 때의 워커 재시작률이 대상이다.
3. Phase 2b enforce의 SOAP 회귀는 상류 PR #24338이 정리될 때 다시 판단한다(상류가 WSDL 오류에서 보호를 풀면, 이 가드는 그 경로에서 이벤트를 내지 않는다).
