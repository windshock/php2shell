# PHP 코어 메모리 안전성·OOM·재진입 관련 공개 기록 조사 (2016–2026)

- **조사 기준일:** 2026-10-23 (한국시간)
- **조사 대상:** PHP 공식 `php/php-src` 이슈/PR/보안 공지, 구 PHP 버그 트래커(bugs.php.net), PHP Foundation 기술감사 및 공식 경위 설명, 개발자 공개 논의
- **연구 질문:** 개별 취약점이 아니라, 수년간 반복된 메모리/상태 불변식 위반과 수정 지연의 공통 원인은 무엇인가?
- **범위의 한계:** 이 문서는 약 10년 범위에서 찾은 **선별된 공개 1차 자료 목록**이다. 모든 이슈·코드 수정·비공개 보안 신고를 전수 수집한 결과가 아니다. `Open` 표기는 열람 당시 추적 시스템상의 상태이며 **최신 릴리스에서 재현됨 또는 원격 공격 가능함을 뜻하지 않는다.**

## 1. 핵심 결론

1. **OOM/bailout 도중의 부분 초기화·불완전한 정리**는 적어도 2018, 2020, 2023, 2026년에 반복 관찰된다. 과거 수정된 개별 버그와 아직 열린 이슈는 구분해야 한다.
2. **Destructor·에러 핸들러·재진입·참조 카운트/GC** 문제는 2016년부터 계속 등장한다. 일부는 명백하게 해결됐고, 일부는 실행 엔진/호환성/성능 탓에 근본 해법 논의가 장기화됐다.
3. **Request lifecycle과 확장 모듈 전역 상태의 소유권** 문제는 2018년 mbstring, 2025년 shutdown UAF, 2026년 SOAP와 OOM 관련 CVE에서 서로 다른 구현으로 나타난다.
4. **방어 구현 시도**는 단지 아이디어가 아니다. Zend allocator 안전장치가 일부 병합됐으며, 별도 HTTP-input heap 격리 PR 등은 병합되지 않은 상태로 공개되어 있다.
5. **ASan UAF와 외부에서 바로 가능한 RCE는 다르다.** 사용자 정의 PHP 코드의 복잡한 실행 조건이 필요한 사례와 공격자가 HTTP 바이트만 제어하면 되는 사례는 완전히 다른 위험 수준이다.

## 2. 10년 연대기 — 원본 기록 목록

표기: **수정**=원본 기록상 해결/병합, **열림**=열람 당시 Open, **대기/검증**=제보만으로는 취약성과 영향 검증 부족, **설계**=방어 개선안 또는 공통 원인 논의.

| 최초 등록/공개 | 자료 | 핵심 실패 패턴 / 검토 가치 | 해당 기록의 상태 | 연결 유형 |
|---|---|---|---|---|
| 2016-07 | [bugs #72530](https://bugs.php.net/bug.php?id=72530) | GC 중 destructor가 객체 참조를 새로 외부 노출시켜 refcount 모델이 놓친 UAF. 조기 종결 후 재개 | 2019-08 수정 기록, 현재 Closed | GC·destructor·지연 수리 |
| 2016-09 | [bugs #73092 / CVE-2016-7479](https://bugs.php.net/bug.php?id=73092) | `unserialize()` 중 객체 프로퍼티 HashTable 재할당이 기존 포인터를 무효화 | Closed | 해시 버킷 포인터·역직렬화 |
| 2016-09 | [bugs #73147](https://bugs.php.net/bug.php?id=73147) | `unserialize()`/`__wakeup()` 중 참조·객체 수명 충돌, 개발자가 일반 해결의 난이도 언급 | 수정 | 재진입·역직렬화 |
| 2017-01 | [bugs #73900](https://bugs.php.net/bug.php?id=73900) | `SplFixedArray` 역직렬화 및 참조 조작으로 UAF/메모리 노출 재현 | 2017-04 Closed | 입력 파싱·객체 레퍼런스 |
| 2017-02 | [bugs #74101 / CVE-2017-12934](https://bugs.php.net/bug.php?id=74101) | AFL/ASan 기반 `unserialize()` UAF 확인 | 2017-08 수정/Closed | 퍼징·역직렬화 |
| 2017-05 | [bugs #74614](https://bugs.php.net/bug.php?id=74614) | 유사 `unserialize()` UAF 중복 문제 | 2017-07 수정/중복 처리 | 중복·회귀 분석 |
| 2018-03 | [bugs #76047](https://bugs.php.net/bug.php?id=76047) | 소멸 객체의 backtrace 인수 참조 UAF | 2020-01 Closed | exception·객체 수명 |
| 2018-03 | [bugs #76167](https://bugs.php.net/bug.php?id=76167) | `mbstring`의 RINIT/RSHUTDOWN 비대칭으로 **이전 요청의 포인터를 다음 요청에서 재사용/해제** | 2021-10 수정/Closed, [PR #7604](https://github.com/php/php-src/pull/7604) | **요청 간 잔존 포인터** |
| 2018-06 | [bugs #76409 / CVE-2018-12882](https://bugs.php.net/bug.php?id=76409) | EXIF 입력 처리의 `_php_stream_free()` UAF | 2018-06 수정/Closed | 외부 입력·스트림 수명 |
| 2018-09 | [bugs #76846](https://bugs.php.net/bug.php?id=76846) | OOM bailout 중 object-store 재할당 실패, 크기 메타데이터 선변경 후 shutdown에서 경계 밖 쓰기 가능 | 2018-09 수정/Closed | **OOM·부분 상태·shutdown** |
| 2018-11 | [bugs #77185](https://bugs.php.net/bug.php?id=77185) | FPM master의 이벤트 처리 중 UAF | 2019-07 Closed | SAPI·worker 생명주기 |
| 2018-12 | [bugs #77249](https://bugs.php.net/bug.php?id=77249) | `xmlrpc_decode()` malformed 입력의 ASan UAF | Duplicate | 외부 파서·중복 |
| 2019-04 | [bugs #77843](https://bugs.php.net/bug.php?id=77843) | JSON serializer 관련 UAF | Closed | 직렬화·취약점 연계 |
| 2019-08 | [bugs #78379](https://bugs.php.net/bug.php?id=78379) | 객체 변환 시 GC와 참조 관리 충돌로 UAF | 2021-07 Closed | GC·캐스팅 |
| 2019-11 | [bugs #78876](https://bugs.php.net/bug.php?id=78876) | multipart 입력에서 OOM 시 임시파일 정리 생략 → 디스크 DoS | 2020-05 수정/Closed | **외부 입력·OOM·cleanup** |
| 2019-11 | [bugs #78793 / CVE-2019-11050](https://bugs.php.net/bug.php?id=78793) | EXIF 입력 파서 UAF | 2019-12 Closed | 파일 입력·UAF |
| 2019-12 | [bugs #79029](https://bugs.php.net/bug.php?id=79029) | XMLReader/XMLWriter 스트림 공유 중 이중 해제/UAF | Closed | 소유권·double-free |
| 2020-06 | [bugs #79760](https://bugs.php.net/bug.php?id=79760) | **GC가 refcount를 줄인 후 `get_gc`가 OOM을 일으키면 `zend_bailout` 뒤 정리 불일치**. PHP 코어 개발자가 직접 원인과 수정 난이도 명시 | **기존 트래커 Open**, 최신 HEAD 재현 별도 검증 필요 | **최우선 OOM/GC 설계 이슈** |
| 2020-07 | [bugs #79784](https://bugs.php.net/bug.php?id=79784) | 경고를 통한 값 변경 후 기존 포인터를 참조하는 UAF | 수정 | 에러 핸들러·재진입 |
| 2021-03 | [bugs #80894](https://bugs.php.net/bug.php?id=80894) | PHP 7.3 `__debugInfo()`→GC 이중 해제. 7.4+ 비영향, 7.3 지원 정책 때문에 수정하지 않음 | **Wont fix** (영향 버전 제한) | 유지보수 정책 판단 |
| 2021-04 | [PR #6903](https://github.com/php/php-src/pull/6903) | opcode 수행 중 warning callback 지연으로 재진입 UAF 방어 시도. 간접 참조 때문에 완전한 해결 아님 | 미병합 | **엔진 설계 변경 미완** |
| 2022-01 | [bugs #81708 / CVE-2021-21708](https://bugs.php.net/bug.php?id=81708) | `FILTER_VALIDATE_FLOAT` 처리 UAF. 웹 요청 상황에서 관찰된 이슈 | 2022-02 수정 | 함수 단위 메모리 안전성 |
| 2022-11 | [Issue #10026](https://github.com/php/php-src/issues/10026), [PR #10283](https://github.com/php/php-src/pull/10283), [PR #24338](https://github.com/php/php-src/pull/24338) | SOAP 실패를 `SoapFault`로 회복시켰지만 `zend_bailout()` 후 `gc_protect(1)`가 남아 이후 모든 GC가 중단. 2026-10 개발자들이 실제 OOM에서는 GC 보호를 함부로 풀 수 없다고 논의 | **Issue Open / Verified**; PR 두 건은 **미병합 종료** | **부분적 오류 복구·장기 미해결·설계 대립** |
| 2022-12 | [Issue #10169](https://github.com/php/php-src/issues/10169) | `ZEND_ASSIGN_OBJ` 계열 heap UAF 보고 | 상태·재현 최신 확인 필요 | VM opcode·재진입 |
| 2023-02 | [Issue #10709](https://github.com/php/php-src/issues/10709) | class constant AST 평가와 autoload 재귀 과정 UAF 보고 | Closed | autoload·재귀 |
| 2023-08 | [Issue #12073](https://github.com/php/php-src/issues/12073) | OOM 중 closure 객체 **부분 초기화** 후 shutdown에서 크래시, 실제 MediaWiki/FPM에서 관찰 | **2023-09-04 수정/Closed** | **OOM·부분 초기화·shutdown** |
| 2023-10 | [Issue #12468](https://github.com/php/php-src/issues/12468) | 문서 주석 `doc_comment` 참조 카운트 오류, shutdown UAF | Closed | refcount·shutdown |
| 2023-11 | [PR #12805](https://github.com/php/php-src/pull/12805) | 경고/에러 콜백 지연 설계의 재시도, JIT/VM의 실행 재개와 레지스터 보존 문제 | **Draft, Open** | **구조적 해결 미완** |
| 2024-04 | [Issue #14083](https://github.com/php/php-src/issues/14083) | Zend heap 메타데이터/프리리스트 보호, guard page, 분리 heap 등 hardened allocator 과제 | **Open, 설계 목록** | exploit mitigation |
| 2024-04 | [PR #13943](https://github.com/php/php-src/pull/13943) | Zend heap 무결성 보호 | **Merged** | **실제 적용된 방어** |
| 2024-05 | [PR #14304](https://github.com/php/php-src/pull/14304) | HTTP GET/POST/환경값 메모리를 별도 heap 영역에 분리 | **Open, 미병합** | heap 격리·공격 제약 |
| 2024-07 | [Issue #15108](https://github.com/php/php-src/issues/15108) | Fiber·Generator 조합에서 GC refcount assertion | 2024-07-30 PR #15158로 수정 | Fiber/GC 수명 |
| 2024-10 | [Issue #16464](https://github.com/php/php-src/issues/16464) | SplDoublyLinkedList destructor 재진입 UAF | Closed | 컨테이너 재진입 |
| 2024-10 | [Issue #16479](https://github.com/php/php-src/issues/16479) | SplObjectStorage destructor 재진입 UAF | Closed | 컨테이너 재진입 |
| 2024-11 | [Issue #16726](https://github.com/php/php-src/issues/16726) | error handler가 수행 중 변수 값을 교체해 opcode가 해제된 메모리를 참조 | **Open / Verified** | **에러 콜백 재진입** |
| 2024년 감사 / 2025-04 공개 | [PHP Foundation 결과](https://thephp.foundation/blog/2025/04/10/php-core-security-audit-results/) · [Quarkslab 원본 PDF](https://thephp.foundation/assets/files/24-07-1730-REP-V1.4_temp.pdf) | 외부 감사 총 27개 발견사항(그중 보안 관련 17개) 정리. 감사 보고 결함과 이후 파생 인지한 OOM 문제는 구분 | 보고서 발행/정리 | 보안 감사·검증 범위 |
| 2025-03 | [GHSA-rwp7-7vc6-8477 / CVE-2024-11235](https://github.com/php/php-src/security/advisories/GHSA-rwp7-7vc6-8477) | `php_request_shutdown()` 과정의 객체 참조 카운트 UAF | 공지 및 수정 완료 | shutdown·예외·참조 |
| 2025-05 | [Issue #18640](https://github.com/php/php-src/issues/18640) | SOAP `soap_check_zval_ref` heap UAF 보고 | 별도 종료·패치 버전 확인 필요 | SOAP·refcount |
| 2025-08 | [Issue #19484](https://github.com/php/php-src/issues/19484) | PostgreSQL 지속 연결에 등록된 콜백이 다음 요청에서 이미 해제된 포인터를 참조할 가능성 보고 | **당일 Closed**; PR 병합 여부/수정 근거 추가 대조 필요 | persistent connection·요청 간 상태 |
| 2025-09 | [Issue #20018](https://github.com/php/php-src/issues/20018) | 이전 재진입 UAF 버그 11건 및 4개의 해결 시도를 공통 문제로 연결 | **Open** | **문제의 계보** |
| 2025-11 | [Issue #20352](https://github.com/php/php-src/issues/20352) | output-handler 에러 해제 중 `ob_start` 재진입 UAF | **2025-12-19 수정/Closed** | 출력·재진입 |
| 2026-03 | [Issue #21499](https://github.com/php/php-src/issues/21499) | `RecursiveArrayIterator`가 부모 HashTable 버킷의 raw pointer를 참조 → 부모 해제 후 UAF | 2026-03 수정/Closed | raw pointer·컨테이너 수명 |
| 2026-05 | [GHSA-85c2-q967-79q5 / CVE-2026-6722](https://github.com/php/php-src/security/advisories/GHSA-85c2-q967-79q5) | SOAP 전역 ref_map의 객체 참조 누락으로 stale pointer; 특정 응용의 원격 공격 가능성 | 보안 공지/수정 | **확장 모듈 전역 상태·RCE** |
| 2026-05 | [GHSA-m33r-qmcv-p97q / CVE-2026-7261](https://github.com/php/php-src/security/advisories/GHSA-m33r-qmcv-p97q) | SOAP 지속 헤더의 객체 수명 UAF | 보안 공지/수정 | SOAP state·lifecycle |
| 2026-06 | [Issue #22526](https://github.com/php/php-src/issues/22526) | parser/scanner에서 `zend_bailout()`으로 정상 정리 경로를 탈출해 메모리 누수 | **Open / Needs Triage** | OOM·bailout·cleanup |
| 2026-07 | [PR #22710](https://github.com/php/php-src/pull/22710) | destructor가 `zend_hash_clean()` 중 bailout → 항목 삭제 기록이 남지 않아 shutdown에서 이중 정리/UAF | **Open PR**, 현재 HEAD 동작 별도 검증 | **bailout·destructor·hash lifecycle** |
| 2026-07 | [Issue #22895](https://github.com/php/php-src/issues/22895) | SOAP 직렬화 UAF/ASan 보고 | Closed | SOAP·객체 수명 |
| 2026-09 | [PHP 개발자 토론](https://discourse.thephp.foundation/t/php-dev-categorising-engine-bugs-caused-by-nonsensical-malicious-callback-handlers-as-undefined-behaviour-and-to-not-fix-them/6037) | 악의적/비정상 콜백의 메모리 오류를 UB로 간주하고 수리 대상을 제한할 것인지 토론 | 공개 의견교환, 공식 채택 미확인 | **보안 책임·정책 판단** |
| 2026-10-15 | [Issue #24361](https://github.com/php/php-src/issues/24361), [php.bugs 보존본](https://news-web.php.net/php.bugs/253005) | `opcache_compile_file()`가 컴파일 오류로 인한 bailout을 잡은 뒤 계속 실행하면서 GC 보호 상태를 복구하지 않아 요청 나머지 구간에서 GC가 비활성화됨. 2022년 #10026의 관련 패턴 | **Open**, 원문에 8.3·8.4·master 재현 기록 | **오류 복구 이후 전역 상태 불변식** |
| 2026-10-16 | [Issue #24373](https://github.com/php/php-src/issues/24373) | `serialize()` 해제 중 destructor의 중첩 `serialize()`가 외부 var_hash를 재사용해 UAF | **2026-10-22 수정/Closed** | 직렬화·재진입·수정 완료 사례 |
| 2026-10-20 | [Issue #24455](https://github.com/php/php-src/issues/24455) | lazy object reset와 destructor 재진입 ASan UAF 제보 | **Open / Needs Triage** | 객체 수명·재진입 |
| 2026-10-21 | [GHSA-w8hw-w9fx-j79w / CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | PHP OOM bailout 후 손상된 상태가 다음 요청/정리 단계에 사용됨 | **공식 보안 패치 공개** | **핵심 조사 대상** |
| 2026-10-21 | [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | OOM/요청 간 상태의 메모리 안전성 문제 | **공식 보안 패치 공개** | **핵심 조사 대상** |
| 2026-10-21 | [Issue #24481](https://github.com/php/php-src/issues/24481) | `unserialize` 재진입 UAF 제보. 작성자의 RCE 표현은 공식 검증 아님; PoC 실행 조건에 PHP 코드 실행이 이미 필요함 | **Open / Needs Triage** | 재진입·재현 조건 엄격 검증 |
| 2026-10-21 | [Issue #24488](https://github.com/php/php-src/issues/24488) | 긴급 릴리스의 SimpleXML/GC 관련 수정 이후 이중 해제 회귀; 별개 코드 베이스에서 영향 확인 | **2026-10-22 수정/Closed**, 후속 릴리스 배포 확인 별도 | **패치 회귀·GC 소유권** |
| 2026-10-21 | [Issue #24489](https://github.com/php/php-src/issues/24489) | `master` 브랜치에서 mbstring bailout 수정 일부가 merge 중 누락됐다는 보고 | **Open** (브랜치별 비교 필요) | 수정 누락·merge 검증 |
| 2026-10-21 | [Issue #24492](https://github.com/php/php-src/issues/24492) | 새 hard memory limit에서 일부 기존 할당 API가 `_exit(137)`로 프로세스를 종료하는 가용성 회귀 | **Open / Needs Triage** | 패치 부작용·allocator API |
| 2026-10-21 | [PHP Foundation 경위 설명](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) | 2024년 잠재 OOM 위험 인지·수정 정책 지연과 인력/의사결정 문제를 공식 인정 | 공식 설명 | 거버넌스·공개 타임라인 |

## 3. 인과관계로 연결할 수 있는 핵심 계보

### 계보 A. OOM → 부분 상태 → bailout → shutdown 문제

- **2018 #76846**: 할당 실패 전 메타데이터를 변경하여 종료 시점에 잘못된 상태가 노출됨. *당시 수정됨*.
- **2020 #79760**: GC refcount 감소 후 `get_gc`의 메모리 부족으로 `zend_bailout()` 발생. *오래된 트래커에서 Open*.
- **2023 #12073**: closure 등록 후 초기화 중 메모리 부족 → shutdown에서 잘못된 필드 접근. *당시 수정됨*.
- **2022 #10026**: SOAP 에러 회복 뒤 `gc_protect(1)`가 계속 유지됨. *현재도 Verified/Open, 제안 PR 두 건은 미병합 종료*.
- **2026 #24361**: Opcache 컴파일 실패를 포착한 뒤에도 GC protection이 요청 나머지 구간에 남음. *2026-10-15 등록/Open*.
- **2026 #22710**: 해시 테이블 cleanup 도중 destructor bailout → 중복 해제 가능. *미병합 PR*.
- **2026 CVE-2026-109618/109619**: 근본적인 OOM unwind 안정성 문제로 긴급 패치. *공식 수정됨*.
- **2026 #24492**: 패치의 soft/hard memory limit 전환 과정에서 가용성 회귀. *제보/미검증*.

주의: 이 항목들은 **동일 코드 경로 하나의 단일 취약점이 아니라**, 실패 후 상태 일관성이라는 공통 설계 불변식과 연관된 역사적 사례이다.

### 계보 B. 재진입 가능한 콜백 / destructor → 원본 포인터 무효화

- **2016 #72530**: destructor가 GC 참조 관계를 바꿈. 사후 수정까지 수년 소요.
- **2021 PR #6903** 및 **2023 PR #12805**: warning callback을 안전 시점까지 지연시키려는 VM 수준 수정 시도.
- **2024 #16726** 및 **2025 #20018**: 문제가 재발하거나 유사한 케이스가 다수 정리됨.
- **2026년 9월 토론**: 악성 콜백 유래 결함을 undefined behavior 취급할 것인지 논쟁. 공식 정책 수립과는 구분.

### 계보 C. 요청 종료 및 확장 모듈 전역 상태의 수명

- **2018 #76167**: `RINIT`/`RSHUTDOWN` 불일치로 다음 요청에서 이전 포인터 참조. 2021 수정.
- **2025 CVE-2024-11235**: `php_request_shutdown`에서 참조 카운트 조작 UAF. 수정.
- **2026 CVE-2026-6722**: SOAP `ref_map`의 stale pointer/참조 관리 누락. 수정.
- **2026 PHP2Shell**: OOM 관련 경로의 다른 상태 관리 실패. 수정.

여기서 중요한 건 **입력 출처(사용자 HTTP 입력·DB·외부 XML·애플리케이션 PHP 코드), 소유권, 요청 생명주기, 성공/실패 경로에서 호출되는 cleanup**을 묶어 모델링하는 것이다.

## 4. 방어 설계: 기존 시도 vs 추가 검증 제안

| 설계 | 근거 | 대상 오류 | 평가 및 남은 질문 |
|---|---|---|---|
| Zend allocator freelist/무결성 강화 | [#14083](https://github.com/php/php-src/issues/14083), [#13943](https://github.com/php/php-src/pull/13943), [#14054](https://github.com/php/php-src/pull/14054) | heap metadata corruption / 공격 악용 억제 | 일부 병합됨. 실제 runtime overhead와 우회 가능성은 빌드 별 평가 필요 |
| HTTP 입력 격리 heap | [PR #14304](https://github.com/php/php-src/pull/14304) | 원격 공격자의 heap grooming 여건 저하 | 미병합, 결함 원인 제거 기능은 아님. extension 호환성·요청 종료 경로 검증 필요 |
| 콜백 안전 시점 지연 | [#6903](https://github.com/php/php-src/pull/6903), [#12805](https://github.com/php/php-src/pull/12805) | 실행 도중 객체/변수 무효화 | VM/JIT 통합, 에러 표시 지연의 언어 호환성 문제 남음 |
| `bailout` 직전 강한 예외 안전성 | [#76846](https://bugs.php.net/bug.php?id=76846), [#12073](https://github.com/php/php-src/issues/12073), [#22710](https://github.com/php/php-src/pull/22710) | partially committed state에서 비정상 탈출 | 상태 변경을 allocation/destructor 앞뒤로 분리, 미완료 슬롯 마킹 등 함수별 정적 검사 규칙 후보 |
| FPM/worker 프로세스 격리 및 오류 격리 | [공식 보안 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | 손상된 상태가 후속 요청까지 전파되는 피해 | 부하 테스트에서 재시작 정책·가용성·RCE 여부를 별도로 측정해야 함 |
| Soft/hard OOM 후속 보완 | [#24492](https://github.com/php/php-src/issues/24492) | 안전한 OOM 복구 vs hard exit | 새 fallible allocator 사용처 전수 추적 및 사용자 입력에서의 crash/no-crash 검증 |

## 5. 연구·검증 우선순위

### P0 — 현재 코드 상태를 먼저 확인할 항목

1. **bugs #79760 + GitHub #10026 + #24361:** 2026 OOM 정책에서 정상/비정상 bailout 이후 GC `protected` 상태를 함수별로 어떻게 복구하는가? 실제 회복하는 경로와 종료하는 경로를 구분해 테스트.
2. **bugs #79760의 독립 재현:** GC 중 `get_gc`가 메모리 제한을 유발하는 경우의 참조 카운트와 자료구조 무결성을 최신 HEAD에서 ASan/UBSan으로 확인. (옛 버그 트래커의 Open 상태를 취약성 증거로 사용하지 않음)
3. **PR #22710:** `zend_hash_clean` 과정의 destructor bailout이 8.2~8.6과 각 보안 패치 브랜치에서 아직 재현되는가? 추가 해제가 가능한가?
4. **Issue #16726 / #20018:** 오류 핸들러 재진입 및 lvalue/INDIRECT 유효성 문제가 최신 HEAD에서 여전히 ASan UAF로 발생하는가?
5. **Issue #24492 / #24489:** 긴급 OOM 패치의 정상 동작/호환성 회귀, 브랜치별 누락 유무 확인.
6. **PR #14304:** 요청 외부 입력 heap을 분리했을 때 2016~2026의 취약점 공격 가능성과 성능에 어떤 변화가 있는가?

### 재현·분류시 반드시 구분할 항목

- **입력 제어 수준:** 원격 HTTP 데이터만 vs 애플리케이션에서 콜백/객체 생성 가능 vs 공격자가 이미 PHP 코드 실행 가능
- **환경 조건:** FPM / Apache mod_php / CLI / FrankenPHP / ZTS / Opcache / JIT / extension 구성
- **영향:** assertion/crash(DoS) / heap corruption(UAF/DF) / 교차 요청 상태 전파 / 정보 유출 / 조건을 증명한 원격 코드 실행
- **현행성:** 최초 보고 버전, 수정 커밋, 수정 포함 브랜치, 현재 HEAD, 최신 릴리스 4개를 분리
- **증명 수준:** 제보자의 설명 / ASan 오류 재현 / 수정 전후 비교 / 신뢰할 수 있는 원격 입력에서 공격 가능성 증명

## 6. 후속 조사에 유용한 검색 범위/문구

- 2016–2021: `bugs.php.net`에서 `bailout`, `memory limit`, `shutdown`, `RINIT`, `RSHUTDOWN`, `unserialize`, `gc`, `destructor`, `use after free`, `double free` 검색.
- 2022–2026: `repo:php/php-src is:issue created:2022-01-01..2026-10-23 "use-after-free"`, `"bailout"`, `"shutdown" "memory_limit"`, `"re-entrancy"`, `"GC"` 등 GitHub 기간 검색.
- 부작용 및 오래된 수정 실패: GitHub PR에서 `is:pr is:closed is:unmerged`, 원인 키워드별 커밋과 중복 이슈 연결 관계를 검토.
- 공개 보안 발표: `github.com/php/php-src/security/advisories`, PHP Foundation, Quarkslab 원본 보고서, PHP 내부 개발자 토론.

**해석상의 제한:** 여기 수록한 소스는 PHP 코어에서 반복적으로 나타나는 위험 영역을 가리키지만, 미패치 고위험 RCE 목록이나 보안팀의 과실 건수를 의미하지 않는다. 현재 컴파일/재현 검증과 소스-level 수정 전후 diff 없이는 새 CVE 확정이나 취약 여부 단정이 불가능하다.
