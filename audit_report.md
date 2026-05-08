# Audit Report: test_cve_2026_31431.py

**Date:** 2026-05-08
**Subject:** `test_cve_2026_31431.py` — CVE-2026-31431 vulnerability detector
**Scope:** Code-level security and correctness review

---

## Summary

The detector is fundamentally sound: its containment boundary is solid, and the behavioral detection logic correctly identifies the page-cache scratch-write primitive. No path was found by which the script can corrupt files outside the user-owned temp directory it creates. Three findings are documented below, ordered by severity. Finding 1 from the original report (`kernel_in_affected_line()` misleading message) has been resolved by removing the function and its call site.

---

## ~~Finding 1 — Medium: `kernel_in_affected_line()` message inverts affected/fixed terminology~~ — RESOLVED

The `kernel_in_affected_line()` function and its call site in `main()` have been removed. The behavioral test in `attempt_trigger()` is the sole and authoritative detection mechanism; no kernel-version heuristic is needed.

---

## Finding 2 — Low: Loading `algif_aead` is an irreversible side effect of detection

**Lines:** 56–60 (`precheck`)

```python
s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
s.bind(("aead", ALG_NAME))
s.close()
```

Binding an AF_ALG socket to `"aead"` causes the kernel to autoload the `algif_aead` module if it is not already present. Once loaded, it stays resident until explicitly unloaded.

On a system where the administrator has not yet applied the `modprobe` mitigation, this behavior is expected and harmless — the module was already loadable. However, in an auditing workflow where the operator intends to check vulnerability *before* deciding whether to block the module, the act of checking is itself the thing that loads it, slightly widening the window.

The secondary risk: on very locked-down systems, the unexpected module load may appear in audit logs and be misattributed.

**Mitigations applied:** The detector now checks `/sys/module/algif_aead` before calling `precheck()`. If the module is already loaded, it says so and proceeds. If it is not loaded, it prints a warning that the module will be autoloaded and prompts `[y/N]` for explicit confirmation; answering anything other than `y` aborts with exit 0. Additionally, if the module was loaded by the run, a reminder to unload it (`sudo rmmod algif_aead`) is printed alongside every detection result.

---

## Finding 3 — Low: Resource leaks in `attempt_trigger()` on non-`OSError` exceptions

**Lines:** 97–122

The pipe and socket handles are released by two separate cleanup paths: an `except OSError` block (lines 105–113) and explicit closes after `recv()` (lines 123–126). Both paths leave resources open when a `RuntimeError` is raised (short-splice, lines 101/104) or when `recv()` raises an `OSError` outside the expected set.

Affected handles in the `RuntimeError` path:
- `pr`, `pw` (pipe) — created at line 97, no `finally` wraps them
- `op` (per-op socket) — closed only on the OSError path or after recv
- `master` (AF_ALG master socket) — same
- `fd_target` — closed only at line 129

Affected handles in the unexpected-`recv`-OSError path (line 118–121):
- all four of the above, for the same reason

**Impact:** Because `main()` always exits immediately after `attempt_trigger()` returns or raises, the OS reclaims all FDs on process exit. There is no security impact. The risk is confusion if the code is ever extracted for use in a longer-lived program.

**Recommendation:** Wrap the body of `attempt_trigger()` in a structured `try/finally` (or use `contextlib.ExitStack`) to ensure deterministic cleanup regardless of exception type.

---

## Finding 4 — Informational: Socket leak in `precheck()` on `bind()` failure

**Lines:** 56–60**

```python
try:
    s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("aead", ALG_NAME))
    s.close()
except OSError as e:
    return f"{ALG_NAME!r} cannot be instantiated ({e.strerror})"
```

If `s.bind()` raises `OSError`, the `except` branch returns without calling `s.close()`. Python's reference-counting GC will eventually close it, but it is not deterministic. On CPython this is immediately reclaimed; on other implementations it may linger.

**Recommendation:** Use a `try/finally` or a context manager:

```python
with socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    s.bind(("aead", ALG_NAME))
```

---

## Containment Analysis

The central security question for a detector that invokes a live LPE primitive is: **can the scratch-write land outside the user-owned sentinel file?**

The answer is no, for the following structural reasons:

1. **`fd_target` is always the sentinel.** It is opened (read-only) from a path under `tempfile.mkdtemp()`, which creates a mode-0700 directory owned by the running user. No other process can place a symlink or replacement file there.

2. **The file is written by the detector itself immediately before being opened.** There is no window between creation and open during which an attacker could substitute a different file.

3. **The splice source is `fd_target` at `offset_src=0`.** Only the sentinel's page-cache page enters the AEAD input scatterlist. The in-place operation (`req->dst == req->src`) writes back to that same page — sentinel page in, sentinel page out.

4. **No elevated privileges are used.** The detector runs entirely as the calling user. The AF_ALG socket family is available to unprivileged users by default; no `suid`, `cap_net_admin`, or file open with escalated rights occurs.

5. **`/etc/passwd`, `/usr/bin/su`, and other system files are never opened.** A `grep` for `open`, `os.open`, and `os.splice` in the file confirms no path outside the temp dir is referenced.

The behavioral test is correctly scoped and cannot be redirected to corrupt an arbitrary file by any means observable in the code.

---

## Detection Correctness Analysis

| Scenario | Expected result | Actual result | Correct? |
|---|---|---|---|
| Patched kernel (algif_aead absent) | Exit 0 | `precheck()` fails → exit 0 | ✓ |
| Patched kernel (algif_aead present, splice blocked) | Exit 0 | `EOPNOTSUPP` → RuntimeError → exit 1 | Marginal — exit 1 vs 0 |
| Vulnerable kernel, marker lands at expected offset | Exit 2 | `marker_off >= 0` → exit 2 | ✓ |
| Vulnerable kernel, marker lands at unexpected offset | Exit 2 | `diffs` non-empty → exit 2 | ✓ |
| Page cache intact after trigger | Exit 0 | No diffs, no marker → exit 0 | ✓ |
| Sentinel already contains `PWND` | Ambiguous | `marker_orig >= 0` → falls through to `diffs` check | ✓ (secondary check fires) |

One edge case: if the kernel blocks `splice` into AF_ALG sockets (`EOPNOTSUPP`) but `algif_aead` is still loadable, `precheck()` passes and the trigger raises a `RuntimeError`, yielding exit 1 ("test error") rather than exit 0 ("not vulnerable"). The system is not exploitable in that configuration, so exit 1 is a false alarm. This is a known limitation documented in the code comment, but worth flagging to operators who may have scripted alerting on exit 2 and silence on 0.

---

## Findings Summary

| # | Severity | Title | Status |
|---|---|---|---|
| 1 | Medium | `kernel_in_affected_line()` inverts affected/fixed terminology | Resolved — function removed |
| 2 | Low | Running detector loads `algif_aead` module as a side effect | Mitigated — prompt + rmmod reminder added |
| 3 | Low | Resource leaks in `attempt_trigger()` on non-`OSError` exceptions | Open |
| 4 | Info | Socket not explicitly closed on `bind()` failure in `precheck()` | Open |

No path to privilege escalation or unintended file corruption was found in the detector.
