# PHP Memory-Safety Historical Corpus — H1 검증 결과

> 생성: `linux/corpus/verify-corpus.py --render` (원천 상태 조회 시각 2026-10-23T09:45:57Z). 원문: `docs/corpus/php-memory-safety-2016-2026.md`(사용자 제공, 수정 없음).
> **이 표는 취약점 목록이 아니다.** 수정 완료·미검증 제보·설계 논의가 섞여 있다. `record_type`은 원천의 현재 상태에서 나온 기록 유형이며, 증거 수준·노출 조건·현재 탐색기 도달 가능성은 H2/H2.5에서 사례별로 판정한다(`unassessed`).

| ID | 최초 | 기록 | 원천 현재 상태 | record_type | 후보 패턴 | 현재 탐색기 도달성(H2.5) | 불일치 |
|---|---|---|---|---|---|---|---|
| R01 | 2016-07 | [bugs #72530] | Closed | fixed | bailout_gc, reentrancy | `needs_php_code` GC + destructor exposing a reference | — |
| R02 | 2016-09 | [bugs #73092 / CVE-2016-7479] | Closed | fixed | input_parser_uaf | `needs_payload_grammar` unserialize of object properties forcing a HashTable realloc | — |
| R03 | 2016-09 | [bugs #73147] | Closed | fixed | reentrancy, input_parser_uaf | `needs_php_code` __wakeup() user class during unserialize | — |
| R04 | 2017-01 | [bugs #73900] | Closed | fixed | other | `needs_payload_grammar` SplFixedArray (SPL is built in) with crafted references | — |
| R05 | 2017-02 | [bugs #74101 / CVE-2017-12934] | Closed | fixed | input_parser_uaf | `needs_payload_grammar` unserialize UAF found by AFL; crafted payload | — |
| R06 | 2017-05 | [bugs #74614] | Closed | fixed | input_parser_uaf | `needs_payload_grammar` duplicate of an unserialize UAF; crafted payload | — |
| R07 | 2018-03 | [bugs #76047] | Closed | fixed | other | `needs_php_code` exception backtrace argument of a destroyed object | — |
| R08 | 2018-03 | [bugs #76167] | Closed | fixed | request_lifetime | `needs_extension` mbstring RINIT/RSHUTDOWN asymmetry (request lifetime) - mbstring not built | — |
| R09 | 2018-06 | [bugs #76409 / CVE-2018-12882] | Closed | fixed | input_parser_uaf | `needs_extension` exif | — |
| R10 | 2018-09 | [bugs #76846] | Closed | fixed | oom_partial_init, bailout_gc, request_lifetime | `needs_php_code` OOM while the object store grows - needs object creation at the limit | — |
| R11 | 2018-11 | [bugs #77185] | Closed | fixed | other | `needs_sapi` FPM master event handling | — |
| R12 | 2018-12 | [bugs #77249] | Duplicate | duplicate | input_parser_uaf | `out_of_scope` xmlrpc was removed from core in PHP 8.0 | — |
| R13 | 2019-04 | [bugs #77843] | Closed | fixed | input_parser_uaf | `needs_php_code` JSON serializer UAF - needs json_encode of crafted objects | — |
| R14 | 2019-08 | [bugs #78379] | Closed | fixed | bailout_gc | `needs_php_code` object conversion with GC interaction | — |
| R15 | 2019-11 | [bugs #78876] | Closed | fixed | oom_partial_init, input_parser_uaf | `needs_oracle` multipart OOM skipping temp-file cleanup (disk DoS) - delivery exists (parse_oom), temp-file leak is not observed | — |
| R16 | 2019-11 | [bugs #78793 / CVE-2019-11050] | Closed | fixed | input_parser_uaf | `needs_extension` exif | — |
| R17 | 2019-12 | [bugs #79029] | Closed | fixed | other | `needs_extension` xmlreader / xmlwriter | — |
| R18 | 2020-06 | [bugs #79760] | Open | open | oom_partial_init, bailout_gc | `needs_php_code` get_gc OOM after GC decremented refcounts - needs objects with get_gc under memory pressure | — |
| R19 | 2020-07 | [bugs #79784] | Closed | fixed | other | `needs_php_code` value changed through a warning (error handler) | — |
| R20 | 2021-03 | [bugs #80894] | Wont fix | wontfix | bailout_gc | `out_of_scope` PHP 7.3 only (wontfix by support policy) | — |
| R21 | 2021-04 | [PR #6903] | closed | unmerged_design | reentrancy | `design_record` unmerged design PR (deferred warning callbacks) | — |
| R22 | 2022-01 | [bugs #81708 / CVE-2021-21708] | Closed | fixed | other | `needs_extension` filter (FILTER_VALIDATE_FLOAT) - --disable-all leaves filter out | — |
| R23 | 2022-11 | [Issue #10026], [PR #10283], [PR #24338] | open; closed; closed | open | oom_partial_init, bailout_gc | `needs_extension` SOAP fault recovery leaving gc_protect(1) - soap not built; effect (GC disabled) also needs an oracle | — |
| R24 | 2022-12 | [Issue #10169] | closed/completed | fixed | allocator_hardening | `needs_php_code` ZEND_ASSIGN_OBJ heap UAF | — |
| R25 | 2023-02 | [Issue #10709] | closed/completed | fixed | other | `needs_php_code` class constant AST evaluation with autoload recursion | — |
| R26 | 2023-08 | [Issue #12073] | closed/completed | fixed | oom_partial_init, request_lifetime | `needs_php_code` closure partial init on OOM, shutdown crash | — |
| R27 | 2023-10 | [Issue #12468] | closed/completed | fixed | request_lifetime | `needs_php_code` doc_comment refcount, shutdown UAF | — |
| R28 | 2023-11 | [PR #12805] | open | open | reentrancy | `design_record` draft PR (deferred error callbacks, JIT/VM resume) | — |
| R29 | 2024-04 | [Issue #14083] | open | open | allocator_hardening | `design_record` hardened allocator task list | — |
| R30 | 2024-04 | [PR #13943] | closed/merged | fixed | allocator_hardening | `design_record` merged Zend heap integrity protection (a defence, input to #3) | — |
| R31 | 2024-05 | [PR #14304] | open | open | allocator_hardening | `design_record` unmerged PR: separate heap for request input | — |
| R32 | 2024-07 | [Issue #15108] | closed/completed | fixed | bailout_gc | `needs_php_code` Fiber + Generator GC refcount assertion | — |
| R33 | 2024-10 | [Issue #16464] | closed/completed | fixed | reentrancy | `needs_php_code` SplDoublyLinkedList destructor re-entry | — |
| R34 | 2024-10 | [Issue #16479] | closed/completed | fixed | reentrancy | `needs_php_code` SplObjectStorage destructor re-entry | — |
| R35 | 2024-11 | [Issue #16726] | open | open | other | `needs_php_code` error handler replacing a variable during an opcode | — |
| R36 | 2024년 감사 / 2025-04 공개 | [PHP Foundation 결과] · [Quarkslab 원본 PDF] | reachable; reachable | design-discussion | oom_partial_init | `design_record` external audit summary | — |
| R37 | 2025-03 | [GHSA-rwp7-7vc6-8477 / CVE-2024-11235] | published | advisory | request_lifetime | `needs_php_code` php_request_shutdown object refcount UAF (CVE-2024-11235) - needs the specific object graph | — |
| R38 | 2025-05 | [Issue #18640] | closed/completed | fixed | allocator_hardening | `needs_extension` soap | — |
| R39 | 2025-08 | [Issue #19484] | closed/completed | fixed | reentrancy | `needs_extension` pgsql persistent connection callback across requests | — |
| R40 | 2025-09 | [Issue #20018] | open | open | reentrancy | `needs_php_code` re-entry UAF family umbrella (11 bugs) - per member | — |
| R41 | 2025-11 | [Issue #20352] | closed/completed | fixed | reentrancy | `needs_php_code` output handler error with ob_start re-entry | — |
| R42 | 2026-03 | [Issue #21499] | closed/completed | fixed | other | `needs_php_code` RecursiveArrayIterator raw bucket pointer | — |
| R43 | 2026-05 | [GHSA-85c2-q967-79q5 / CVE-2026-6722] | published | advisory | request_lifetime | `needs_extension` soap global ref_map | — |
| R44 | 2026-05 | [GHSA-m33r-qmcv-p97q / CVE-2026-7261] | published | advisory | other | `needs_extension` soap persistent headers | — |
| R45 | 2026-06 | [Issue #22526] | open | open | bailout_gc | `needs_oracle` parser/scanner bailout leaking memory - needs PHP source to compile and a leak oracle | — |
| R46 | 2026-07 | [PR #22710] | open | open | bailout_gc, reentrancy, request_lifetime | `needs_php_code` destructor bailing out during zend_hash_clean | — |
| R47 | 2026-07 | [Issue #22895] | closed/completed | fixed | other | `needs_extension` soap serialization | — |
| R48 | 2026-09 | [PHP 개발자 토론] | reachable | design-discussion | reentrancy | `design_record` developer discussion on malicious callbacks as UB | — |
| R49 | 2026-10-15 | [Issue #24361], [php.bugs 보존본] | open; reachable | open | bailout_gc | `needs_extension` opcache_compile_file bailout leaving GC protected - opcache not in the asan builds; effect needs an oracle | — |
| R50 | 2026-10-16 | [Issue #24373] | closed/completed | fixed | reentrancy | `needs_php_code` nested serialize() from a destructor reusing the outer var_hash | — |
| R51 | 2026-10-20 | [Issue #24455] | open | open | reentrancy | `needs_php_code` lazy object reset with destructor re-entry | — |
| R52 | 2026-10-21 | [GHSA-w8hw-w9fx-j79w / CVE-2026-109618] | published | advisory | oom_partial_init, bailout_gc | `reachable_now` CVE-2026-109618 (P15, mod_php profile) | — |
| R53 | 2026-10-21 | [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619] | published | advisory | oom_partial_init, request_lifetime | `reachable_now` CVE-2026-109619 (P16/P17, Bug S) | — |
| R54 | 2026-10-21 | [Issue #24481] | open | open | reentrancy, input_parser_uaf | `needs_php_code` unserialize re-entry UAF; the report itself needs PHP code execution | — |
| R55 | 2026-10-21 | [Issue #24488] | closed/completed | fixed | bailout_gc | `needs_extension` simplexml (regression of the emergency release) | — |
| R56 | 2026-10-21 | [Issue #24489] | open | open | bailout_gc | `needs_extension` mbstring bailout fix merge gap (master branch) | — |
| R57 | 2026-10-21 | [Issue #24492] | open | open | other | `reachable_now` hard memory limit _exit(137) availability regression - reachable with the OOM producers on 8.4.27; worker loss is observed | — |
| R58 | 2026-10-21 | [PHP Foundation 경위 설명] | reachable | design-discussion | oom_partial_init | `design_record` PHP Foundation statement | — |

**요약:** advisory 5, design-discussion 3, duplicate 1, fixed 33, open 14, unmerged_design 1, wontfix 1 (총 58). 원천 조회 실패 0.

**H2.5 도달성(judged_from_record_text):** design_record 8, needs_extension 14, needs_oracle 2, needs_payload_grammar 4, needs_php_code 24, needs_sapi 1, out_of_scope 2, reachable_now 3. 범주 정의: `reachable_now` = the trigger is expressible with the existing actions and build; `needs_oracle` = reachable, but the effect (leak, disk DoS, GC disabled, process exit) is not observed by the current oracle; `needs_payload_grammar` = reachable through the lab /unserialize endpoint only with crafted serialized payloads (grammar extension); `needs_php_code` = needs application PHP code (user classes, destructors, error handlers, GC/Fiber use) - e.g. a fused_program action; `needs_extension` = needs an extension that the lab builds do not compile in; `needs_sapi` = needs a SAPI behaviour the profiles do not exercise; `out_of_scope` = removed extension or unsupported version; `design_record` = design discussion / hardening / meta record - informs #3, not a hold-out case
