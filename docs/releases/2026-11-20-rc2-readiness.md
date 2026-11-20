# RC2 readiness status — 2026-11-20

HEAD: `140595c` (origin/main, LIVE)

## Gates (all green, run 2026-11-20)

| Gate | Result |
|------|--------|
| `cargo test --workspace` | 228 passed / 0 failed / 1 ignored |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 errors, 0 warnings |
| `scripts/check-tree-hygiene.sh` (S1: no redb/large files in tree) | OK |
| `git status` | clean |
| `scripts/e2e_smoke.py` vs live daemon | 58/58 checks passed |

## Closed this cycle (E1/E2)

- E1 closed: replacement cache + `evict_dead`/`evict_addr` in routing (M-16/H-3), peer-score half-life decay 24h, eviction by score (`fail≥5 && fail≥2·success`), secret redaction in `log_ev!` (API token registered at startup; recursion deadlock fixed + regression test), token-gated `/metrics`, M-18 non-ASCII panic fix, `req_timeouts` loss counter + 10s `recv_req_frame` on ping/fetch/por.
- E2: disk quotas (cap + 2x free-space headroom), scheduled self-audit PoR (`NEXXUS_POR_AUDIT_SECS`, default 6h, sample 64 chunks), client-side peer PoR audit `audit_peer_por` + RPC `node_audit_peer` (scheduled loop audits up to 8 peers, `por.peers_audit`).
- Bugs found by e2e and fixed: `por_task` exiting on `POR_AUDIT_SECS=0` killed the whole daemon via select! (`ddc1944`); bundle export/import PBKDF2-600k blocked the tokio worker → moved to `spawn_blocking` (`34fe0d0`); smoke ws timeout 5s→30s (`140595c`).

## Known non-blockers

- STUN/hole-punching: deferred (must not break onion profile).
- PoR penalty in desktop UI: pending.
- C-6/C-7/C-8 (TON contracts): blocked by design until Func/Tolk migration; `deploy` jobs and `ton-contracts` CI disabled.
- Desktop CI webkit2gtk on runner: infra, outside RC scope.

## Release readiness

**80%** — core node (P2P, storage, vault, econ accounting, backups, bundles, PoR) verified by unit + e2e. Remaining % is platform packaging (Windows MSI/service polish, Android native) and the TON settlement track.
