# PHP 코어 긴급 취약점(PHP2Shell) — Executive Summary

**문서 상태:** v3 (Phase 5·이슈 #1 반영) · 2026-10-23 KST
**기준:** `windshock/php2shell` main 최신 커밋(2026-10-23) · 증적 매니페스트 [docs/evidence-manifest-20261023.sha256](evidence-manifest-20261023.sha256)
**분석 범위:** PHP 8.4.4·8.5.4 → 수정 8.4.27 교차 검증, 격리된 로컬 랩, 정적 코드 검증 및 공개 연구 대조. 운영 서비스의 침해 여부는 조사 범위에서 제외.

> **한 줄 결론:** PHP 보안팀이 공식 확인한 **Critical RCE 2건**이며 **패치가 유일한 완전한 해결책**이다. 자체 랩에서는 **CVE-2026-109619 계열(잔류 전역 상태) UAF를 재현**하고 **8.4.27에서 소멸**함을 확인했다. 자체적으로 RCE를 재현한 것은 아니다.

## 1. 핵심 판단

1. **공식 사실:** 두 건 모두 **CVSS v4.0 9.2**, 인증 없이 애플리케이션 코드 실행 전에 트리거될 수 있는 RCE. 공식 수정 버전은 **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**이며, **PHP 8.1 이하**는 업스트림 지원이 종료되어 벤더 백포트에만 의존한다.[1][2][3]
2. **초기 공개 PoC의 원인 설명은 반박됨:** `post_bytes_processed` 포인터 UAF 주장은 PHP 원본의 `Z_TRY_ADDREF(progress->data)` 참조 유지 동작과 모순된다(8.4.4·8.5.4 동일, 랩 전 조합 ASAN 오류 0).
3. **대신 확인된 경로:** 요청 파싱 중 (un)serialize가 모듈 RINIT보다 먼저 실행되고, 비정상 종료 시 `BG(serialize)`/`BG(unserialize)` 컨텍스트 정리가 생략되어 **다음 요청이 해제된 메모리를 재사용**한다. 랩 재현: CLI 5/5, Apache mod_php 3/3 + 2/2, 모두 `heap-use-after-free`(ASAN 3종 스택 일치). **추가(2026-10-22): Calif가 정의한 3개 중단 지점을 모두 자체 재현했다** — ① 109618 부분 초기화 HashTable(키 할당 fatal `zend_hash.c:958` → teardown SEGV, 3/3), ② 109619 PS 전역 상태(mod_php 3/3 + GDB 체크리스트), ③ 109619 post-RINIT `BG(unserialize)`(FPM 앱 실행 중 생산자 → 워커 생존 → 다음 요청 재사용, 3/3). 전 경로 8.4.27에서 소멸.
4. **패치 효과 확인:** 8.4.27에서 동일 입력 재실행 결과 **PoC 0/5, ASAN 0, 잔류 0**. 공식 Diff는 `php_basic_early_rinit()`(요청 시작 직후 BG 상태 리셋)과 `PS(in_rfc1867_update)` 기반 직렬화 범위 제한을 추가해 **자체 분석과 동일 메커니즘**을 수정한다.
5. **WAF 단독 방어 불가:** ModSecurity 2.9.7에서 필드명만 검사하는 룰은 10가지 multipart 변형 중 **2건을 통과시키면서 PHP는 해당 파라미터를 처리**했다(중복 `name`, 추가 파라미터). 룰을 보강해도 이 2건은 그대로여서 **실질 위험 감소는 0**이며, 문자열 기반 룰은 가상패치가 아니다.
6. **미검증:** 자체 RCE 체인, 무인증 원격 단독 진입, 실제 운영 환경의 침해 여부.

## 2. 공식 사실 vs 자체 검증

| 구분 | 공식 확인 | 자체 검증 결과 |
|---|---|---|
| **CVE-2026-109618** (OOM corruption, GHSA-w8hw-w9fx-j79w) | `_zend_hash_str_add_or_update_i`의 **count-before-key-allocation** → 부분 초기화 Bucket을 mod_php 종료가 소비 | **재현·패치 후 소멸 확인(2026-10-22)** — 키 할당 fatal(`zend_hash.c:958`, GDB 백트레이스) → `zend_array_destroy` SEGV 3/3; 8.4.27은 fatal 자체 미발생(전달 차단). 착지가 카운터 이전(28M 대조)일 때는 크래시 없음을 입증 |
| **CVE-2026-109619** (stale global state, GHSA-6wmf-4rv5-p3rp) | 해제된 메모리를 가리키는 요청 소유 상태가 후속 요청에서 재사용 | **재현·패치 후 소멸 확인 — 세 경로 모두**: `BG(serialize)`/`BG(unserialize)` pre-RINIT(CLI·mod_php), **PS 전역 상태**(mod_php 3/3, GDB로 `modules_activated=0`·RSHUTDOWN 스킵·동일 `PS(id)` 재사용 관측), **post-RINIT 앱 실행 중 생산자**(FPM 3/3, 워커 생존→재사용) |
| 초기 공개 PoC(포인터 UAF) | 공식 원인 아님 | 원본 코드 참조 카운트 분석으로 **반박** |
| WAF 필드명 룰 | 완전한 완화책 아님 | 10변형 중 **2건 통과·PHP 도달** 실측 |
| SAPI별 동작 | mod_php 최고 위험, FPM도 다른 경로 검증 | FPM은 요청 시작 실패 시 **워커 종료(exit 70)** 로 해당 시퀀스 소멸. 단, 이는 **안전 근거가 아님** |

## 3. 패치 전후 검증 (8.4.4 → 8.4.27)

| 항목 | 8.4.4 (취약) | 8.4.27 (수정) |
|---|---|---|
| PoC 5회 반복 | 5/5 UAF | **0/5, ASAN 보고 없음** |
| `BG(serialize)` 잔류 | level=1 → 재사용 → UAF | **잔류 0** |
| `BG(unserialize)` 잔류 | level=1 → 재사용 → UAF | **잔류 0** |
| 동일 HTTP 입력 비교 | 기준 | `identical` |

**판정:** `patch_effect_confirmed`(랩 범위) · `root_cause_confirmed`(CVE-2026-109619) · **`root_cause_confirmed`(CVE-2026-109618, 2026-10-22 추가 — 지정 사이트 재현 + 전달 차단 소멸 + 공식 Diff 영역 일치)**
**증적:** SHA-256 매니페스트([docs/evidence-manifest-20261022.sha256](evidence-manifest-20261022.sha256), 4,370파일), `verify-evidence` 통과.

## 4. 사업 영향과 대응 우선순위

공식 확인된 최대 영향은 **웹 워커 권한의 임의 코드 실행, 민감정보 유출, 서비스 변조·장애**다. 조직 내 실제 취약 자산 수·인터넷 노출·악용 시도·침해 여부는 **별도 확인이 필요하다**.

| 우선순위 | 대응 | 유의사항 |
|---|---|---|
| **즉시** | 외부 공개 PHP 자산의 버전·SAPI·배포판·패치 상태 파악 | **mod_php 우선**, FPM·CGI·FrankenPHP·LiteSpeed도 제외하지 않음. CMS·NAS·벤더 번들 `php` 포함 |
| **즉시** | 공식 수정 릴리스 또는 벤더 보안 패치 적용 + **전 워커 재시작** + 회귀 점검 | **패치가 유일한 완전한 해결책**. 컨테이너는 베이스 이미지가 아닌 실행 컨테이너 교체 확인 |
| **즉시** | PHP 8.1 이하 EOL 자산 식별 | 업스트림 패치 없음 → 벤더 백포트 확인 또는 격리·업그레이드 |
| **패치 전** | `session.upload_progress.enabled=0`을 서버 시작 단계에서 적용 후 재시작 | 109619의 **확인된 세션 경로만** 축소. `ini_set`/`.user.ini` 의존 금지 |
| **패치 전** | 불필요한 multipart 차단, 프록시/컨테이너 수준 본문·필드·파트 수 제한 | 서비스 영향 확인. **완전한 가상패치로 보고하지 않음** |
| **조건부** | OOM·오류 상태 완화 설정 검토 (`memory_limit=-1`, 낮은 `post_max_size`, 8.5는 `fatal_error_backtraces=0`) | `memory_limit=-1`은 가용성 위험 → cgroup/컨테이너 격리와 함께 결정 |
| **보안관제** | OOM, 비정상 multipart, 연속 500/502, 워커 크래시·재시작, 초기화·종료 오류의 상관분석 (초안 룰: `linux/detect-rules/`) | **징후 탐지와 실제 악용 확정은 구분** |

## 5. 결론 및 남은 검증

이 사안은 **공개 PoC의 진위 논쟁이 아니라 공식 확인된 Critical RCE 위험**으로 관리해야 한다. 자체 분석의 기여는 ① 잘못된 PoC 원인 설명의 반박, ② 요청 간 내부 상태와 SAPI 차이를 계측 대상으로 전환, ③ 패치 전후 소멸 검증, ④ WAF 룰의 실제 한계 실측, ⑤ **Calif 3경로의 전 경로 독립 재현과 소멸 형태별 구분(2026-10-22)** — 소비 지점 리셋(Path B), 요청 시작 BG 리셋(Path C), OOM 전달 차단(Path A) — 이다.

**남은 검증:** ① 배포판 패키지·백포트 버전의 실제 적용 확인, ② 실서비스 WAF와 PHP의 파싱 일치 점검·오탐 평가, ③ Sigma 룰의 SIEM 적용 검증, ④ gzip 입력 필터 등 남은 OOM 전달 arm의 다른 구성 시험(P18 참조). — 3경로 재현 자체는 완료(§8). **신규 경로 탐색(2026-10-23, §9): 패치 범위 밖 잔존 경로 미발견(`not_found`, 탐색 스코프 한정).**

---

### 참고 근거

[1] [PHP 공식 보안 공지 (2026-10-21)](https://www.php.net/archive/2026.php)
[2] [GHSA-w8hw-w9fx-j79w — CVE-2026-109618, OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
[3] [GHSA-6wmf-4rv5-p3rp — CVE-2026-109619, stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
[4] [자체 분석 결과 보고서](https://github.com/windshock/php2shell/blob/main/docs/php2shell-analysis-findings.md)
[5] [분석 계획 및 판정 기준](https://github.com/windshock/php2shell/blob/main/docs/php2shell-analysis-plan.md)
[6] [증적 SHA-256 매니페스트](https://github.com/windshock/php2shell/blob/main/docs/evidence-manifest-20261021.sha256)
[7] [Calif — A Tale of Two PHP Remote Vulnerabilities](https://calif.io/php2shell/) — 3개 중단 지점·OOM 전달 기법 대조(§7, §9.14)

*검증 경계: 자체 실험은 격리 환경의 메모리 오류·요청 처리·WAF 동작을 대상으로 하며, 자체 RCE 또는 실제 운영 환경의 침해를 입증하지 않는다. 공식 권고의 RCE 확인과 자체 실험의 재현 수준은 구분해 해석해야 한다.*
