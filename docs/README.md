# 문서 안내 (docs index)

PHP2Shell 분석 산출물의 읽는 순서와 역할입니다.

| 문서 | 대상 독자 | 내용 |
|---|---|---|
| [php2shell-executive-summary.md](php2shell-executive-summary.md) | 경영·보안 리더십 | 결론, 공식 사실 대조, 대응 우선순위 (2쪽) |
| [php2shell-analysis-findings.md](php2shell-analysis-findings.md) | 기술 보안·분석가 | 정적 분석(S1~S8), E2E(P1~P13), 주장별 판정표, Phase 4(8.4.27) 결과 |
| [php2shell-analysis-plan.md](php2shell-analysis-plan.md) | 분석 수행자 | 단계별 계획, 판정 어휘, 외부 연구 방법론 통합표, Phase 4 엄격 판정 규칙 |
| [linux-environment.md](linux-environment.md) | 인프라·랩 운영 | WSL2/ASAN/FPM 빌드·검증 환경과 증적 수집 |
| [php2shell-llm-handoff.md](php2shell-llm-handoff.md) | 후속 담당자 | 인수인계, 검토 지적별 처리 내역, 모니터링 이력 |
| [evidence-manifest-20261021.sha256](evidence-manifest-20261021.sha256) | 검증 담당자 | 증적 2,839개 SHA-256 목록(원본은 `var/linux-evidence/`) |

## 도구 위치

| 목적 | 파일 |
|---|---|
| 환경 검증(기존) | `linux/run.py`, `linux/matrix.py`, `linux/audit.py`, `linux/compare.py`, `linux/export.py` |
| HTTP E2E | `linux/probe.py`, `linux/probe-matrix.sh` |
| 상태 계측 | `linux/gdb-probe.py`, `linux/gdb-unserialize.py` |
| PoC(트리거) | `linux/poc-bgserialize.py` |
| SAPI 랩 | `linux/build-apache.sh`, `linux/apache-lab.sh`, `linux/apache-poc-matrix.sh` |
| WAF 대조 | `linux/waf-lab.sh`, `linux/waf-compare.py` |
| Fuzzer / JIT | `linux/build-fuzzer.sh`, `linux/fuzz-smoke.sh`, `linux/build-jit.sh`, `linux/jit-compare.sh` |
| 패치 검증 | `linux/phase4.sh`, `linux/patch-diff.sh`, `linux/verify-evidence.py` |

Windows 진입점은 루트의 `*.cmd`를 사용합니다(`linux-lab.cmd`, `linux-probe.cmd`, `linux-gdb.cmd`, `linux-export.cmd` 등).
