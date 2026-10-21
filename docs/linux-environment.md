# PHP 취약점 분석·검증용 Linux 환경

이 문서는 기존 Windows 기본 구동 환경에 부족했던 Linux FPM, ASAN, 디버거, 할당기 비교와 증적 수집 환경을 설명한다. **환경 준비와 CVE 취약 판정은 별개**다. 공식 영향 범위와 회귀 테스트가 확인되기 전에는 이 환경의 정상 동작 결과를 안전 판정으로 사용하지 않는다.

## 실제 확인한 항목 (2026-10-21)

- PHP 8.4.4 normal/ASAN 빌드 성공. source commit·컴파일 플래그·바이너리 해시 저장.
- 보고서의 별도 요청 간 UAF 연구에 사용된 PHP 8.5.4도 ASAN 빌드와 소스 디버깅 확인 완료.
- ASAN 양성 대조에서 UAF와 파일 줄 번호 확인, GDB에서 실제 PHP 소스 스택 확인.
- 8.4.4 normal/ASAN과 8.5.4 ASAN에서 각각 6개(할당기 3종 × 버퍼링 on/off), 총 18개 환경 조합 통과. 각 조합에서 PHPT 3개와 HTTP 세션·업로드 검증 완료.
- Windows cmd의 curl → WSL nginx → ASAN FPM 연결과 실제 설정 확인, Ctrl+C로 서버 종료 확인.
- 비교 도구 양성 대조: normal/debug의 의도적인 출력 차이를 감지. 이는 CVE가 아닌 도구 검증.
- 비교 도구 음성 대조: SKIP 결과는 `inconclusive`/종료코드 2, 공란 advisory는 실행 거부.
- 증적 내보내기 확인. Linux 파일 권한 메타데이터는 Windows에 복사하지 않고 파일 내용만 복사한다.
- 최종 감사: `var/linux-evidence/evidence/environment-status.json`. 환경 상태는 `ready_for_analysis_and_regression_execution`, CVE 판정은 `not_run`, 공식 수정 버전은 `not_confirmed`로 구분한다.

## 설치 구성

- WSL2, Ubuntu-24.04, x86_64. 설치 시점 커널: `6.18.54.1-microsoft-standard-WSL2`.
- Clang 18, AddressSanitizer 런타임, LLVM symbolizer, GDB, nginx, PHP 빌드 의존성.
- Linux 사용자 `phplab`: 관리자 권한 없이 컴파일과 nginx/FPM 실행. 암호/로그인은 구성하지 않았다.
- 소스·빌드·런타임·기본 증적: `/home/phplab/php-lab`.
- Windows 프로젝트: `C:\Users\user\Downloads\php`, Linux 경로 `/mnt/c/Users/user/Downloads/php`.
- nginx 서비스 자동 시작은 비활성화했다. 실험 스크립트가 시작한 프로세스만 종료한다.

## 빌드와 출처

```bat
linux-build.cmd 8.4.4 normal
linux-build.cmd 8.4.4 asan
linux-build.cmd 8.5.4 asan
```

`linux/build.sh`는 PHP 공식 Git 저장소의 `php-8.4.4` 태그를 clone하고 수정되지 않은 소스로 별도의 디렉터리에 빌드한다. PHP 핵심 소스에 PoC용 변경을 하지 않는다. 8.4.4의 실제 커밋은 `3786cff1f3f3d755f346ade78979976fee92bb48`이다. 릴리스 태그 객체의 SHA와 실제 커밋 SHA는 다를 수 있다.

| 빌드 | 용도 | 설정 |
|---|---|---|
| `8.4.4-normal` | Zend 기본 할당기를 사용하는 비계측 대조군 | debug off, ASAN off, 최적화 및 디버그 심볼 |
| `8.4.4-asan` | 메모리 오류 및 소스 스택 확인 | debug on, `--enable-address-sanitizer`, frame pointer, debug symbols |
| `8.5.4-asan` | 보고서의 별도 직렬화 상태 연구와 같은 PHP 버전 | debug on, ASAN, frame pointer, debug symbols |

각 빌드는 CLI/FPM/session을 포함하는 최소 확장 구성이다. PHP 8.5.4에는 내장 Zend OPcache도 포함된다. 일반 배포판의 모든 확장, Apache mod_php 또는 실제 운영 서비스 전체 구성을 복제하지 않는다. PHP configure가 debug 빌드에 적용한 실제 최적화와 플래그는 `build-manifest.json`의 `makefile_flags`에 기록한다. `normal`에도 디버그 심볼을 남겨 GDB에서 사용할 수 있다.

빌드마다 소스 커밋, configure 옵션, 실제 CFLAGS, 컴파일러, 커널, CLI/FPM 바이너리 SHA-256을 다음에 저장한다.

```text
/home/phplab/php-lab/install/<version>-<flavor>/build-manifest.json
/home/phplab/php-lab/logs/build-<version>-<flavor>.log
```

다른 공식 정식 버전도 `linux-build.cmd 8.x.y asan` 형식으로 추가할 수 있다. 입력한 버전의 공식 태그가 없으면 실패한다. 다른 버전을 임의로 수정 버전이라고 부르지 않는다. 빌드는 메모리 사용을 줄이기 위해 `make -j2`로 수행한다.

## 계측기와 단위 테스트 확인

```bat
linux-lab.cmd calibrate
linux-lab.cmd calibrate --version 8.5.4
```

작은 C 프로그램 `linux/asan-probe.c`의 의도적인 UAF를 ASAN으로 감지하고, `heap-use-after-free`와 소스 파일 줄 번호가 기록되는지 확인한다. 이것은 PHP CVE 재현이 아닌 계측기 양성 대조 실험이다. 추가로 실제 ASAN PHP의 `php_request_startup`에 GDB 중단점을 걸어 PHP 소스 줄 번호가 있는 스택을 확보한다.

각 `verify` 실행 전 공식 `run-tests.php`로 다음 PHPT 세 개를 실행한다. 통과 개수가 3이 아니면 HTTP 확인 단계로 진행하지 않는다.

1. 공식 `session_encode_basic.phpt`.
2. 공식 `session_decode_basic.phpt`.
3. 로컬 `serialize_session.phpt`: 세션 인코딩/디코딩과 serialize/unserialize 왕복.

전체 PHP 회귀 테스트나 CVE 회귀 테스트를 모두 실행한 것으로 간주하지 않는다.

## FPM 통합 환경 확인

```bat
linux-lab.cmd verify --flavor normal --allocator zend
linux-lab.cmd verify --flavor asan --allocator tracked --buffering off
linux-matrix.cmd 8.4.4 asan
linux-matrix.cmd 8.4.4 normal
linux-matrix.cmd 8.5.4 asan
```

`verify`는 nginx → FPM → PHP의 HTTP 응답, 세션 쿠키 유지, multipart 임시 업로드 파일의 SHA-256을 확인한다. FPM은 워커 하나로 고정하고 연속 요청 전후 PID가 같은지 검사한다. 실제 HTTP 응답에서 PHP 버전, SAPI(`fpm-fcgi`), debug 여부, 할당기 환경변수도 확인한다. 서버는 일반 사용자 권한으로 loopback `18085`(HTTP), `19084`(FastCGI)에만 바인딩한다.

| allocator | USE_ZEND_ALLOC | USE_TRACKED_ALLOC | 확인 목적 |
|---|---|---|---|
| zend | 1 | 0 | 기본 Zend MM에서의 동작 |
| system | 0 | 0 | 시스템 할당기 사용 시 동작 |
| tracked | 0 | 1 | 시스템 할당기를 사용하고 요청 종료 시 추적 할당 해제 |

`matrix`는 위 세 모드 × nginx request buffering on/off의 6개 조합을 확인한다. 현재 확인한 세 빌드를 합하면 18개 환경 조합이다. 같은 코드라도 할당기와 요청 초기화 시점에 따라 결과가 달라지므로 기본 모드의 무크래시를 안전의 근거로 삼지 않는다.

`USE_TRACKED_ALLOC`은 PHP 원본이 제공하는 모드다. 보고서의 연구자가 사용한 별도 힙 한도 계측 패치까지 적용한 것은 아니다. 해당 연구의 OOM 조건을 똑같이 재현하려면 원본과 계측 변경본을 구분하고 추가 조건을 기록해야 한다.

실험 서버를 유지하고 외부 테스트 클라이언트를 연결하려면:

```bat
linux-lab.cmd serve --flavor asan --allocator tracked --buffering off
```

다른 cmd에서 `curl http://127.0.0.1:18085/health`를 사용할 수 있다. 중지는 Ctrl+C. serve도 PHPT와 기본 HTTP 사전 확인을 거친 뒤 대기한다. `verify`/`matrix`는 자동 종료한다. 포트가 이미 점유되어 있으면 기존 서버를 종료하거나 대신 테스트하지 않고 실패한다. 각 실행의 설정 파일과 로그는 서로 다른 디렉터리에 저장한다.

## 로그와 증적 내보내기

```bat
linux-export.cmd
```

Linux의 증적을 Windows 프로젝트의 `var/linux-evidence/`에 복사한다. 실험용 세션 데이터만 들어가며 운영 세션이나 인증 정보를 사용하지 않는다.

- `evidence/<실행>/result.json`: 버전·할당기·설정·검사 결과·워커 재사용·종료 여부.
- `phpt.log`: PHPT 통과/실패/스킵 내역.
- `fpm-error.log`, `fpm-access.log`, `fpm-console.log`: FPM 오류·요청·워커 출력.
- `nginx-error.log`, `nginx-access.log`, `nginx-console.log`: HTTP 계층 로그.
- `asan.<pid>`: 오류가 발생한 프로세스의 ASAN 할당/해제/사용 스택. 정상 확인에서는 생성되지 않는다.
- `evidence/calibration-<version>/asan-probe.log`, `php-gdb.log`: 계측 양성 대조와 PHP 디버거 확인.
- `builds/<버전-모드>/build-manifest.json`, `logs/`: 빌드 출처와 전체 빌드 로그.

ASAN은 leak 검사를 끄고 UAF 등의 메모리 오류에서 중단하도록 설정한다. 이는 누수 검사가 이번 검증에 포함되지 않음을 뜻한다. ASAN 파일이 발견되면 `verify` 결과를 실패로 처리한다. 초기 구성 실패 로그도 삭제하지 않고 보존한다.

## 패치 전후 비교 준비와 판정 제한

2026-10-21 구축 중 확인한 PHP 공식 사전 공지는 Critical 두 건과 23:00 KST 공개 예정을 안내하지만 CVE별 영향·수정 버전을 제공하지 않았다. **공식 수정 버전은 이 문서에서 지정하지 않는다.** 예상 버전이나 로컬 임의 수정을 공식 패치로 취급하지 않는다.

공식 발표 후에는 동일한 빌드 모드로 영향 버전과 수정 버전을 각각 빌드하고, `linux/advisory.template.json`의 공란을 공식 근거로 채운 별도 JSON을 만든다. 공식 회귀 PHPT와 필요한 fixture 파일들을 전용 폴더에 준비한다. 예시(자리표시자는 실제 값으로 교체):

```bat
wsl -d Ubuntu-24.04 -u phplab --cd /mnt/c/Users/user/Downloads/php --exec python3 linux/compare.py --before AFFECTED-asan --after FIXED-asan --test /path/to/regression.phpt --advisory /path/to/advisory.json
```

비교 도구는 두 빌드의 실제 버전이 advisory와 일치하는지 확인하고, 서로 분리한 테스트 폴더에서 PHPT를 실행한다. 공지 필드가 비었거나 빌드가 같으면 실행을 거부한다. before 실패·after 성공이 아니거나 SKIP/BORK/XFAIL/WARN이 있으면 `inconclusive`로 남긴다. 실패·성공 차이가 있어도 자동으로 CVE 취약/안전을 선언하지 않는다. 비교 스크립트는 환경 구분과 증적 수집을 위한 것이며, 공식 패치 미공개 상태에서 실제 CVE의 패치 전후 검증이 완료된 것은 아니다.

판정에는 적어도 공식 영향 범위, 정확한 빌드·SAPI·설정, 해당 결함을 자극하는 입력, ASAN 또는 회귀 테스트 증거, 패치 후 동일 조건에서의 변화가 필요하다. 이 환경에서 재현되지 않았다는 사실만으로 다른 SAPI·확장·설정까지 안전하다고 결론 내리지 않는다.

## 참고 원문

- WSL 설치: https://learn.microsoft.com/en-us/windows/wsl/install
- PHP 공식 소스/CI 빌드: https://github.com/php/php-src/tree/php-8.4.4
- AddressSanitizer: https://clang.llvm.org/docs/AddressSanitizer.html
- PHP 긴급 릴리스 공지: https://www.php.net/archive/2026.php#2026-10-20-1
