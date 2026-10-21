# PHP 분석 및 E2E 준비 환경

사용자 요청 범위는 **취약점 검증을 위한 환경 구축과 문서화**이다. 보고된 CVE의 트리거, OOM, RCE 재현은 수행하지 않는다. ASAN 계측 확인에는 별도의 작은 C 프로그램으로 의도적인 UAF 오류를 발생시킨다.

작업 위치: `C:\Users\user\Downloads\php`

## 구축 확인 결과 (2026-10-21)

- Windows PHP 8.4.4 실행 및 원본 소스 다운로드 완료.
- Microsoft Visual C++ x64 재배포 런타임을 winget으로 14.51.36247.0 버전으로 업데이트하여 PHP 시작 시 DLL 버전 불일치를 해결했다.
- `python scripts/lab.py smoke` 종료 코드 0. HTTP health, 세션 쿠키 왕복, 25바이트 정상 multipart 업로드와 SHA-256 일치 확인.
- 확인 후 테스트 PHP 서버 종료 완료. 취약점 재현은 수행하지 않았다.
- Linux 환경은 이후 WSL2 + Ubuntu 24.04로 보완했다. 실제 빌드·검증 내역과 사용 방법은 [Linux 검증 환경 문서](docs/linux-environment.md)를 따른다.

## Windows에서 바로 사용

Python 3.10 이상을 사용하며 추가 Python 패키지는 필요 없다. 프로젝트 전용 PHP 8.4.4 NTS x64를 `runtime/php-8.4.4`에 설치한다. 전역 PHP PATH는 변경하지 않는다. 8.4.4는 보고서의 실험 기준 버전이며 이번 CVE에 대한 취약/수정 판정을 의미하지 않는다.

cmd.exe에서:

```bat
cd /d C:\Users\user\Downloads\php
python scripts\lab.py setup
smoke.cmd
start.cmd
```

`setup`은 공식 Windows PHP ZIP과 공식 php/php-src의 `php-8.4.4` 소스 ZIP을 다운로드한다. 다운로드는 임시 파일을 거쳐 저장하며 기존 캐시가 있으면 재사용한다. 재실행 시 런타임과 소스의 같은 파일은 다시 추출되므로 소스 수정 작업은 별도 복사본에서 진행한다. Windows에는 호환되는 Microsoft Visual C++ x64 재배포 런타임이 필요하다.

`start.cmd`는 `127.0.0.1:18084`에서 포그라운드 실행한다. 종료는 Ctrl+C. 포트를 바꾸려면 `start.cmd --port 18086`을 사용한다. Windows CLI 서버는 Linux FPM/Apache와 다르며, 해당 환경의 요청 간 메모리 동작이나 취약점 재현 결과를 대신하지 않는다.

다른 cmd.exe 창에서:

```bat
curl http://127.0.0.1:18084/health
curl -c var\cookies.txt http://127.0.0.1:18084/session
curl -b var\cookies.txt http://127.0.0.1:18084/session
curl -F "file=@README.md" http://127.0.0.1:18084/upload
```

`/upload`는 파일을 영구 저장하지 않고 PHP 임시 업로드 파일의 크기와 SHA-256만 응답한다. `/session`은 세션 방문 횟수를 기록한다. `/health`는 버전, SAPI, 업로드 진행 설정과 직렬화 핸들러를 반환한다. 프로젝트 전체가 아닌 `web/`만 문서 루트로 사용한다.

## 환경 확인의 범위와 증적

`smoke.cmd`는 전용 PHP 자식 프로세스를 시작해 건강 확인, 쿠키 기반 세션 유지, 정상 multipart 파일 전송과 해시 일치를 확인한 뒤 프로세스를 종료한다. 서버가 이미 사용 중인 포트에서는 실패한다. 취약점 E2E 테스트가 아닌 환경 점검이다. 실제 실행 결과는 `var/smoke-result.json`, 서버 로그는 `var/logs/server-smoke.log`, PHP 오류는 `var/logs/php-error.log`에서 확인한다.

`var/download-manifest.json`에는 다운로드 URL과 실제 수신 파일의 SHA-256이 기록된다. 이 해시는 향후 동일 파일 비교용으로, 벤더 서명 또는 별도로 검증한 공식 체크섬을 대체하지 않는다.

## 분석 자료

- **분석 계획**: [docs/php2shell-analysis-plan.md](docs/php2shell-analysis-plan.md) — 패치 전 확인·분석·E2E 테스트 계획(외부 검토 의견 반영 포함).
- **분석 결과**: [docs/php2shell-analysis-findings.md](docs/php2shell-analysis-findings.md) — 정적 분석(S1~S8), 동적 E2E(P1~P8), 주장별 판정표.
- **E2E 프로브**: `linux/probe.py`(HTTP), `linux/gdb-probe.py`(GDB 상태 계측), `linux/probe-matrix.sh`(순차 매트릭스).
- **증적**: `var/linux-evidence/` + `evidence-manifest.sha256`(SHA-256).
- 원본 소스: `sources/php-src-php-8.4.4/` (ZIP 내부 디렉터리 이름 기준).
- 우선 검토 위치: `ext/session/session.c`, `ext/session/php_session.h`, `ext/standard/var.c`, `ext/standard/basic_functions.c`, `main/main.c`, `main/php_variables.c`, `main/rfc1867.c`.
- 보고서의 `Z_TRY_ADDREF(progress->data)` 포인터 수명 가설과 `BG(serialize)` 요청 간 상태 가설을 별도로 검증해야 한다.
- 소스는 원본 상태를 유지한다. 향후 공식 수정 버전이 확정되면 별도 소스/런타임을 준비해 비교한다.

## Linux FPM 검증 환경

주 검증 환경은 WSL2 Ubuntu 24.04의 nginx + 소스에서 빌드한 PHP-FPM이다. 일반 빌드와 ASAN 디버그 빌드, 세 가지 메모리 할당 모드, 요청 버퍼링 on/off, PHPT, 소스 수준 디버깅과 로그 수집을 제공한다. [상세 사용법과 판정 기준](docs/linux-environment.md)을 확인한다.

```bat
linux-lab.cmd verify --flavor asan --allocator tracked
linux-lab.cmd serve --flavor asan --allocator tracked
```

아래 Docker Compose 구성은 별도 대안이며 Docker 부재로 실행하지 않았다. ASAN 검증에는 위 WSL 환경을 사용한다.

```bat
docker compose up -d
curl http://127.0.0.1:18085/health
docker compose logs
docker compose down
```

이 Docker 대안은 loopback 18085만 공개하며 FPM 포트는 호스트에 공개하지 않는다. 서비스 간 네트워크는 internal이다. 이미지 digest는 고정하지 않았고 ASAN은 포함하지 않는다. WSL 주 환경과 같은 HTTP 포트를 사용하므로 동시에 실행하지 않는다.

## cmd.exe 도구

- curl: `C:\Windows\System32\curl.exe`, 버전 8.21.0. 기존 설치와 cmd 실행을 확인했다.
- Claude Code: `C:\Users\user\.local\bin\claude.exe`, 버전 2.1.306. Anthropic Authenticode 서명 Valid를 확인했다. 기존 설치 디렉터리를 사용자 PATH에 추가했다.
- Git Bash: `C:\Program Files\Git\bin\bash.exe`. 사용자 환경변수 `CLAUDE_CODE_GIT_BASH_PATH`로 지정했다.
- 변경한 PATH는 새 cmd.exe 창에서 반영된다. `claude --version`으로 확인하고 `claude`로 시작한다. 계정 로그인은 사용자가 직접 진행한다.

## 원문

- PHP Windows 아카이브: https://downloads.php.net/~windows/releases/archives/
- PHP 8.4.4 소스: https://github.com/php/php-src/tree/php-8.4.4
- PHP CLI 서버: https://www.php.net/manual/en/features.commandline.webserver.php
- Claude Code 공식 설치: https://code.claude.com/docs/en/setup
