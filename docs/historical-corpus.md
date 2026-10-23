# PHP Memory-Safety Historical Corpus — H1 검증 결과

> 생성: `linux/corpus/verify-corpus.py --render` (원천 상태 조회 시각 2026-10-23T09:45:57Z). 원문: `docs/corpus/php-memory-safety-2016-2026.md`(사용자 제공, 수정 없음).
> **이 표는 취약점 목록이 아니다.** 수정 완료·미검증 제보·설계 논의가 섞여 있다. `record_type`은 원천의 현재 상태에서 나온 기록 유형이며, 증거 수준·노출 조건·현재 탐색기 도달 가능성은 H2/H2.5에서 사례별로 판정한다(`unassessed`).

| ID | 최초 | 기록 | 원천 현재 상태 | record_type | 후보 패턴 | 불일치 |
|---|---|---|---|---|---|---|
| R01 | 2016-07 | [bugs #72530] | Closed | fixed | bailout_gc, reentrancy | — |
| R02 | 2016-09 | [bugs #73092 / CVE-2016-7479] | Closed | fixed | input_parser_uaf | — |
| R03 | 2016-09 | [bugs #73147] | Closed | fixed | reentrancy, input_parser_uaf | — |
| R04 | 2017-01 | [bugs #73900] | Closed | fixed | other | — |
| R05 | 2017-02 | [bugs #74101 / CVE-2017-12934] | Closed | fixed | input_parser_uaf | — |
| R06 | 2017-05 | [bugs #74614] | Closed | fixed | input_parser_uaf | — |
| R07 | 2018-03 | [bugs #76047] | Closed | fixed | other | — |
| R08 | 2018-03 | [bugs #76167] | Closed | fixed | request_lifetime | — |
| R09 | 2018-06 | [bugs #76409 / CVE-2018-12882] | Closed | fixed | input_parser_uaf | — |
| R10 | 2018-09 | [bugs #76846] | Closed | fixed | oom_partial_init, bailout_gc, request_lifetime | — |
| R11 | 2018-11 | [bugs #77185] | Closed | fixed | other | — |
| R12 | 2018-12 | [bugs #77249] | Duplicate | duplicate | input_parser_uaf | — |
| R13 | 2019-04 | [bugs #77843] | Closed | fixed | input_parser_uaf | — |
| R14 | 2019-08 | [bugs #78379] | Closed | fixed | bailout_gc | — |
| R15 | 2019-11 | [bugs #78876] | Closed | fixed | oom_partial_init, input_parser_uaf | — |
| R16 | 2019-11 | [bugs #78793 / CVE-2019-11050] | Closed | fixed | input_parser_uaf | — |
| R17 | 2019-12 | [bugs #79029] | Closed | fixed | other | — |
| R18 | 2020-06 | [bugs #79760] | Open | open | oom_partial_init, bailout_gc | — |
| R19 | 2020-07 | [bugs #79784] | Closed | fixed | other | — |
| R20 | 2021-03 | [bugs #80894] | Wont fix | wontfix | bailout_gc | — |
| R21 | 2021-04 | [PR #6903] | closed | unmerged_design | reentrancy | — |
| R22 | 2022-01 | [bugs #81708 / CVE-2021-21708] | Closed | fixed | other | — |
| R23 | 2022-11 | [Issue #10026], [PR #10283], [PR #24338] | open; closed; closed | open | oom_partial_init, bailout_gc | — |
| R24 | 2022-12 | [Issue #10169] | closed/completed | fixed | allocator_hardening | — |
| R25 | 2023-02 | [Issue #10709] | closed/completed | fixed | other | — |
| R26 | 2023-08 | [Issue #12073] | closed/completed | fixed | oom_partial_init, request_lifetime | — |
| R27 | 2023-10 | [Issue #12468] | closed/completed | fixed | request_lifetime | — |
| R28 | 2023-11 | [PR #12805] | open | open | reentrancy | — |
| R29 | 2024-04 | [Issue #14083] | open | open | allocator_hardening | — |
| R30 | 2024-04 | [PR #13943] | closed/merged | fixed | allocator_hardening | — |
| R31 | 2024-05 | [PR #14304] | open | open | allocator_hardening | — |
| R32 | 2024-07 | [Issue #15108] | closed/completed | fixed | bailout_gc | — |
| R33 | 2024-10 | [Issue #16464] | closed/completed | fixed | reentrancy | — |
| R34 | 2024-10 | [Issue #16479] | closed/completed | fixed | reentrancy | — |
| R35 | 2024-11 | [Issue #16726] | open | open | other | — |
| R36 | 2024년 감사 / 2025-04 공개 | [PHP Foundation 결과] · [Quarkslab 원본 PDF] | reachable; reachable | design-discussion | oom_partial_init | — |
| R37 | 2025-03 | [GHSA-rwp7-7vc6-8477 / CVE-2024-11235] | published | advisory | request_lifetime | — |
| R38 | 2025-05 | [Issue #18640] | closed/completed | fixed | allocator_hardening | — |
| R39 | 2025-08 | [Issue #19484] | closed/completed | fixed | reentrancy | — |
| R40 | 2025-09 | [Issue #20018] | open | open | reentrancy | — |
| R41 | 2025-11 | [Issue #20352] | closed/completed | fixed | reentrancy | — |
| R42 | 2026-03 | [Issue #21499] | closed/completed | fixed | other | — |
| R43 | 2026-05 | [GHSA-85c2-q967-79q5 / CVE-2026-6722] | published | advisory | request_lifetime | — |
| R44 | 2026-05 | [GHSA-m33r-qmcv-p97q / CVE-2026-7261] | published | advisory | other | — |
| R45 | 2026-06 | [Issue #22526] | open | open | bailout_gc | — |
| R46 | 2026-07 | [PR #22710] | open | open | bailout_gc, reentrancy, request_lifetime | — |
| R47 | 2026-07 | [Issue #22895] | closed/completed | fixed | other | — |
| R48 | 2026-09 | [PHP 개발자 토론] | reachable | design-discussion | reentrancy | — |
| R49 | 2026-10-15 | [Issue #24361], [php.bugs 보존본] | open; reachable | open | bailout_gc | — |
| R50 | 2026-10-16 | [Issue #24373] | closed/completed | fixed | reentrancy | — |
| R51 | 2026-10-20 | [Issue #24455] | open | open | reentrancy | — |
| R52 | 2026-10-21 | [GHSA-w8hw-w9fx-j79w / CVE-2026-109618] | published | advisory | oom_partial_init, bailout_gc | — |
| R53 | 2026-10-21 | [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619] | published | advisory | oom_partial_init, request_lifetime | — |
| R54 | 2026-10-21 | [Issue #24481] | open | open | reentrancy, input_parser_uaf | — |
| R55 | 2026-10-21 | [Issue #24488] | closed/completed | fixed | bailout_gc | — |
| R56 | 2026-10-21 | [Issue #24489] | open | open | bailout_gc | — |
| R57 | 2026-10-21 | [Issue #24492] | open | open | other | — |
| R58 | 2026-10-21 | [PHP Foundation 경위 설명] | reachable | design-discussion | oom_partial_init | — |

**요약:** advisory 5, design-discussion 3, duplicate 1, fixed 33, open 14, unmerged_design 1, wontfix 1 (총 58). 원천 조회 실패 0.
