# #7 P0 — 상태 지문·쌍 집계 스키마 사전등록 (2026-10-24, 계획 §15.2)

> 실행 전 동결(#7 P0). 추출기 `linux/state-pairs.py`가 같은 정의를 코드로 삽입한다. 읽기 전용 — 기존 캠페인 증적만 읽고 아무것도 쓰지 않는다(출력은 별도 증적 디렉터리).

## 1. 필드 정의 (동결)

- **state_fingerprint**: exec의 해당 스텝 **startup 경계** 원시 STATE 스냅샷을 `lifecycle-explore.normalize_state` 의미론(모듈 직접 import — 재구현 금지)으로 정규화한 문자열 + 명시 접미 `modules_activated,gc_enabled,gc_active,gc_protected`(원시 관측에 있으나 S키없는 필드 — 20:35 검토 주의 ① "포함·제외 동결" 결정). 포함(S키 전체): `ser/unser 레벨, POINTER_FIELDS(null/fresh/carried), ps_status, vars, hosts, lock` + 위 접미. 제외: `pid, tag, uri`(정체성·위치) 및 **`gc_runs`(이력 카운터 — 이력 차이가 상태 차이로 위조되므로 동등성 키 불가)**. 주소 원값은 정규화로 이미 부재.
- **prefix_trace**: 해당 경계 이전 같은 exec의 스텝 행동열 + 문맥 — `a1>a2>…|limit=<L>,fault=<F>` (스텝 `a` 이름만; 파라미터 제외 — 유한 알파벳 원칙).
- **worker_epoch**: `(exec_서수, 스텝_서수)` — 요청 하나가 워커 생애에서 차지하는 위치. pid는 별도 기록(동등성 키 아님 — #7 정의).
- **observation_completeness**: `complete`(해당 스텝 startup 스냅샷 존재) / `partial`(스텝 응답은 있으나 스냅샷 결측 — gdb 관측 실패) / `missing`(시퀀스 중단으로 미실행). **전 쌍에 공통 한계 플래그 `boundary_only: true`** — 관측은 요청 경계뿐, 요청 내부 차이는 보이지 않는다(주의 ④).
- **source_commit / binary_sha256**: run `summary.json`(없으면 `provenance-note.json`의 effective_commit). **버전·플레이버·SAPI·바이너리가 다르면 절대 합치지 않는다.**

## 2. 쌍 자격 (동결)

같은 fingerprint + 다른 prefix_trace + 양쪽 `complete` + **같은 fault/limit 부류**(fault=0 ↔ fault>0 는 쌍 금지 — 8.4.27은 요청마다 주입 재설정, 주의 ②) + 같은 빌드 문맥. 같은 fingerprint에 prefix가 n개면 후보 쌍 C(n,2) — 보고는 fingerprint별 prefix 집합 + 대표 쌍.

## 3. 가짜 동일성 격리 (동결)

- fingerprint에 `carried` 표시가 하나라도 있으면 `carried_involved: true` — 주소 재사용이 동일성/차이를 위조할 수 있어 **확정 쌍에서 분리 보고**.
- shutdown 스냅샷이 startup과 불일치(다음 경계 관측 결측)한 경계는 `partial`로 강등.
- "관측 불가"는 `unknown`이지 `같음`이 아니다(#7 정의) — 결측 필드가 있으면 그 경계는 completeness 강등.

## 4. 산출물·Go 게이트 (동결)

- `model-candidates.json`: fingerprint별 {prefixes, epochs, 샘플 exec, flags} + 대표 쌍(차후 P1 구별 실험 입력).
- 집계: fingerprint 수, 다중-prefix fingerprint 수, 후보/확정 쌍 수, carried 격리 수, completeness 분포.
- **Go 게이트(P1 진입 조건)**: ①확정 쌍 ≥ 유의미 샘플(동결: ≥20) ②후속 관측 계약 — 각 쌍에 대해 `p1+q`,`p2+q`를 새 프로세스에서 실행하는 재실행 질의 형식이 정해짐 ③질의 예산 산정 — 과거 런 통계(execs/초)로 쌍당 검증 비용(자기 대조 포함 ~6실행) 추정. 미충족 시 No-Go 보고.
