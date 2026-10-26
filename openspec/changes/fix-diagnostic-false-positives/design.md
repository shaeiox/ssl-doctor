# Design

## Context

See proposal.md (Why). The audit evidence is:
- `ssl-doctor-diagnostic-audit.md` in the session scratchpad;
- its reproduction scripts in `audit2/` next to it, which run against the repository's own fixtures.

Each defect has an exact location:

| Item | Where | What goes wrong |
|---|---|---|
| A | `local.py:177` | `ok = rc == 0 and "Expired" not in stdout and "ERROR" not in stdout.upper()`. |
| B | `services.py:253-272` | "permission" only if *every* problem line matches `_PERMISSION`. nginx's always-present `configuration file … test failed` defeats it. `analyze.py:583-588` makes any FAIL a confirmed cause. |
| C | `server.py:1835-1844` | The "belongs to another block" test ignores that the selected block has the same SHA-256. `listen` is recorded but never compared with the scanned port. |
| D | `netchecks.py:1325-1331`, `local.py:39` | The `Date` header is stored without a receive time. Skew is computed when the local check runs, which with `/local` can be long after `/tls`. `Age` is ignored. The clock rule (`analyze.py:388`) fires on any `tls.verify` FAIL. |
| F | `server.py:1486` | `stat -c '%U %G %a %F'` without `-L`, so a symlink reports `777`. `%F` is never evaluated. |
| G | `server.py:866-880` | Every probe error goes to `/dev/null`, so an unreadable source looks empty. `services.py:355` falls back to *any* schedule (`or r.schedules`). |
| H | `analyze.py:88-91` | `decides_verdict` exempts only transport kinds and `_SESSION_CHECKS`. |

**Constraints:**
- Stdlib-only CLI.
- Every remote command is read-only: no sudo, no reload, no signals.
- `findings/1.7` is published with v0.11.0. Its schema enumerates observations and failure kinds, so this change must not add enum values.
- The baseline guard `tests/baseline/record.py --check` must show no removed test ids.

## Goals / Non-Goals

**Goals:**
- Each fix is local to its check. No new module, no new check id, no schema change.
- Regression tests use real tool output and real file layouts, so the fixture gaps that hid B and F cannot recur.

**Non-Goals:**
- No privilege escalation, not even opt-in.
- No ACL interpretation: only their presence is detected.
- No locale-aware parsing of certutil.
- Audit item I (chainval cache and test order) is excluded.

## Decisions

### D1. certutil: exit status decides, the final line only adds the error code
- **Rule:** PASS iff `returncode == 0`. On FAIL, the evidence takes the code from `-verify command FAILED: (0x[0-9a-f]+)` when present; otherwise from `returncode` as an unsigned hex number.
- **URL failures:** lines matching `Error retrieving URL` or `Failed "(AIA|CDP|OCSP)"` become a reachability evidence line. They never decide the status.
- **Decoding:** `text=True, errors="replace"`. `OSError` is caught and gives NOT TESTED.
- **Alternative considered:** keep the substring check and add an allow-list (`dwErrorStatus=0`, …). Rejected: it stays locale- and version-fragile. The exit status is certutil's documented contract.
- **Limitation:** on localised Windows the reachability line is not detected (the English regex). The status is still correct.

### D2. Configuration test: classify error-level lines only
- **Error-level lines:**

| Service | Lines |
|---|---|
| nginx | `\[(emerg\|alert\|crit)\]` |
| Apache | `^AH\d{5}:`, `Syntax error` |
| HAProxy | `\[(ALERT\|ERROR)\]` |

- **Summary lines** are recognised and set aside: `syntax is ok`, `test is successful`, `configuration file .* test failed`, `Syntax OK`.
  - `syntax is ok` is kept in the evidence as "parsing succeeded".
- **Classification:**

| Exit status | Error-level lines | Result |
|---|---|---|
| None | — | `unknown` |
| 0 | — | `pass` |
| ≠ 0 | none | `unknown`, i.e. NOT TESTED `command-failed` with the last lines. Before this change it was FAIL. |
| ≠ 0 | all match the access pattern (`permission denied`, `(13:`, `must be root`, `operation not permitted`) | `permission` |
| ≠ 0 | otherwise | `fail` |

- The `permission` result names the paths it could not open, extracted from `open() "…"` and `fopen(…)`.
- **Alternative considered:** just add the summary line to the permission pattern. Rejected: it fixes only nginx and keeps the "any word" approach.
- **Alternative considered:** opt-in `sudo -n nginx -t`. Rejected for now. It would change the read-only guarantee and needs its own decision (proposal, out of scope).

### D3. Clock skew: keep the reference with its timing
`check_https` records, for the response whose `Date` is used:
- `server_time` (parsed `Date`, plus a valid integer `Age`);
- `server_time_received` (local epoch right after `getresponse()`);
- `server_time_rtt` (from the request start to `getresponse()`);
- `server_time_host`;
- `server_time_age`.

These are runtime facts only; nothing is added to the exported contract facts.

`check_os_and_clock` uses them as follows:
- `skew = server_time_received − server_time`.
- If `now − server_time_received > 120` → NOT TESTED "reference is n s old".
- `uncertainty = 1 + rtt`. The thresholds compare `|skew| − uncertainty` with 60 and 300.
- The clock rule in `analyze.py` additionally requires a `tls.verify` evidence text of "certificate is not yet valid", "certificate has expired" or "certificate expired". These are OpenSSL's verify strings and are already used elsewhere in the rule set.

Alternatives considered:
- Remember the local time inside the local check. Rejected: the local check has no access to when the response arrived.
- An NTP query. Rejected: it adds a network dependency and UDP/123, which is often blocked.

### D4. Permissions: judge the target, report the link
- **Probe:** one remote command per path prints:
  - `stat -c '%F' -- p` (the link type);
  - `readlink -f -- p`;
  - `stat -L -c '%U %G %a %F' -- p`;
  - the ACL marker: the 11th character of `ls -ldL -- p` is `+`.
- **Errors:** a `stat -L` error containing "Permission denied" gives NOT TESTED `permission-denied` (parent not traversable). Other errors keep `command-failed`.
- **Judgement** runs on the target's owner, group and mode. The evidence reads `link -> target (role): owner= group= mode=`, plus "ACL present: additional access not evaluated".
- An ACL adds an uncertainty and never changes the status on its own.
- **Recommendation:** names the target path; `chmod 600` when the master user owns the file; `chmod 640 <owner>:<group>` when a group is needed.
- **Alternative considered:** resolve paths once via `realpaths()` and stat the result. Rejected: two round-trips, and a race between them.

### D5. Inventory: identity first, then listeners
- `_inventory_blocks` additionally records each block's listen ports: the default 443 for `listen` without a port; `[::]:443` and `*:443` are parsed as port 443. `nginx_scan`'s port is stored in `scan_context["inventory_port"]`.
- Blocks that do not listen on that port are listed with "other listener" and are never candidates.
- **When the presented SHA-256 equals the selected block's SHA-256:**
  - other blocks with the same SHA-256 are tagged "shares the certificate";
  - no "belongs to" warning is raised;
  - a covering block with a different certificate on the same port still warns.
- **When the presented SHA-256 is unknown:** covering candidates go to `Finding.uncertainty` and the status stays PASS (spec: no warning for that reason alone). No new observation value is used, because the 1.7 enum is published.
- **Alternative considered:** a new observation `inventory-unconfirmed`. Rejected: it would invalidate 1.7 documents against the released schema.

### D6. Renewal: visibility markers per source
The probe prints `@@SSLDOCTOR visible <source> yes|no` for each source:
- `timers`, decided by whether `systemctl` runs;
- `/etc/crontab`, `/etc/cron.d`, `/etc/cron.daily`;
- `/var/spool/cron/crontabs`, `/var/spool/cron`;
- `/root/.acme.sh`, `$HOME/.acme.sh`.

Directories need `-r` and `-x`; files need `-r`. A missing source counts as visible: it was looked at and is absent.

`parse_renewal` collects the `hidden` sources. `renewal_for` changes as follows:
- **Schedule matching:** the `or r.schedules` fallback is removed. A schedule counts only when it names the managing tool.
- **`unscheduled` with any hidden schedule source** → state `hidden`, which gives NOT TESTED `permission-denied` naming those sources.
- **`none` with a hidden acme.sh home** → NOT TESTED, naming it.

### D7. Verdict: client-machine FAILs are weighed like session failures (decision U1)
`Unexplained.decides_verdict` adds `not self.check.startswith("local.")`. Cause rules are unchanged, so a *confirmed* client cause still makes the verdict FAIL. The HTML and agent reports rebuild the verdict from the same `Diagnosis`, so no report code changes.

## Decisions requiring approval before implementation

**Approved 2026-10-26 by the maintainer: U1 option (b) and U2 = 120 seconds.**

**U1 (H).** How should an unexplained client-machine FAIL count?

| Option | Behaviour |
|---|---|
| **(b) WARNING (recommended; specs written for it)** | The verdict and exit code describe the endpoint. The finding stays listed under unexplained. |
| (a) A separate client verdict | Needs a contract field, so a 1.8 schema. Larger change. |
| (c) Unchanged | Rely on A and D being fixed. Any future false FAIL from a local check would again fail the endpoint. |

**U2 (D).** The reference-freshness window is 120 seconds. A longer window tolerates slow interactive sessions; a shorter one makes a stale reference less likely to pass.

## Risks / Trade-offs

- **[A] An exit status of 0 trusts certutil completely** → certutil's exit status is its documented contract. The final status line is still shown in the evidence for a human to check.
- **[B] An unknown service's error format** → a non-zero exit without recognised error-level lines is NOT TESTED `command-failed`, never PASS. A genuine error is not hidden; it is not asserted either.
- **[B] A real error masked as a permission problem** → only when *every* error-level line is an access error. One non-access `[emerg]` keeps the result FAIL (spec scenario "Genuine error next to a permission error").
- **[D] Scripts relying on exit code 1 for client-side problems (H/U1)** → documented as BREAKING in the CHANGELOG. Confirmed client causes still exit 1.
- **[F] `stat -L` follows a link outside the expected tree** → only metadata is read, never content, as before.
- **[G] More NOT TESTED results on unprivileged hosts** → this is the honest result. The evidence names the unreadable sources, so an operator can re-run with an account that can read them.
- **[C] Listen parsing misses an exotic form (unix socket, variables)** → an unparseable `listen` counts as "can answer", which keeps today's behaviour, never fewer warnings than warranted.

## Migration Plan

1. Archive `fix-chain-diagnosis-saas-enterprise` and `fix-tls-handshake-timeout-attribution`, then `complete-certificate-diagnostics`. This change's MODIFIED deltas for `tls-service-discovery` and `server-certificate-deployment` need those capabilities in `openspec/specs/` (`openspec validate` reports this as INFO today).
2. Implement on a feature branch in the order of tasks.md. Each group is independent and is committed separately.
3. Release as a patch version (0.11.1). The contract and schema stay 1.7.
4. Rollback: revert the commit of the affected group. No data or schema migration exists.

## Open Questions

- The exact Apache and HAProxy permission-error wording on current distributions. The test fixtures can be refined when captured output is available; the classification rule does not change.
