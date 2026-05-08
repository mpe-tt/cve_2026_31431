# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Important: Authorized Use Only

This repository contains a vulnerability detector and local privilege escalation (LPE) proof-of-concept for CVE-2026-31431. Use only on hosts you own or are explicitly engaged to assess. **Do not improve, augment, or extend the exploit code (`exploit_cve_2026_31431.py`) beyond what already exists.**

## Running the scripts

```sh
# Detect vulnerability (safe, operates only on a temp sentinel file)
python3 test_cve_2026_31431.py
# Exit 0 = not vulnerable, 2 = vulnerable, 1 = test error

# LPE dry-run (patches /etc/passwd page cache, auto-evicts on exit)
python3 exploit_cve_2026_31431.py

# LPE with root shell (interactive — su prompts for your own password)
python3 exploit_cve_2026_31431.py --shell
```

No build step, no dependencies. Requires Python 3.10+ (uses `os.splice()` and `tuple[...]` type hints).

## Architecture

Two standalone scripts; no shared modules.

### `test_cve_2026_31431.py` — Detector

1. `precheck()` — verifies `AF_ALG` socket family and `authencesn(hmac(sha256),cbc(aes))` can be instantiated by an unprivileged process.
2. `attempt_trigger(path)` — writes a 4 KiB sentinel file, populates its page cache with a known pattern, then fires the vulnerability primitive against it and returns the before/after page contents.
3. `kernel_in_affected_line()` — heuristic check against kernel version strings (6.12+, 6.17+, 6.18+ are patched); used for informational output only.
4. `main()` — orchestrates the above; cleans up the temp dir regardless of outcome.

The detector only ever touches the sentinel file it creates in a `tempfile.mkdtemp()` directory.

### `exploit_cve_2026_31431.py` — LPE

1. `write4(target_path, file_offset, four_bytes)` — the core primitive. Sends 8-byte AAD (bytes 4–7 = `four_bytes`) via `sendmsg`+cmsg, splices 32 bytes of `target_path`'s page-cache page at `file_offset` into the AF_ALG op socket, drives `recv()`. The `authencesn` scratch-write copies AAD bytes 4–7 into the destination scatterlist (the spliced page-cache page) at the given offset. The `recv()` returns `EBADMSG` (auth failure expected), but the write has already landed.
2. `find_uid_field(path, username)` — parses `/etc/passwd` (as raw bytes) to locate the byte offset of the 4-character UID field for the given username.
3. `main(argv)` — finds the UID field, calls `write4` to overwrite it with `b"0000"`, verifies via re-read and `pwd.getpwnam()`, then either prints next steps or `execvp("su", ...)`.

### Core mechanism shared by both scripts

- **AF_ALG socket setup**: `SOCK_SEQPACKET` on `AF_ALG = 38`, bind to `("aead", ALG_NAME)`, `setsockopt(SOL_ALG=279, ALG_SET_KEY=1, keyblob)`, `accept()` for the per-op socket.
- **Key blob format**: `struct rtattr { u16 rta_len=8; u16 rta_type=1 } || __be32 enckey_len || authkey || enckey`
- **Per-op cmsg**: `ALG_SET_OP=3` (DECRYPT=0), `ALG_SET_IV=2` (16-byte zero IV), `ALG_SET_AEAD_ASSOCLEN=4` (8 bytes).
- **Splice chain**: `os.splice(file_fd → pipe_write)` then `os.splice(pipe_read → op_fd)`. This places the file's page-cache pages directly into the AEAD destination scatterlist.

## Mitigation (for reference)

```sh
sudo tee /etc/modprobe.d/disable-algif-aead.conf <<<'install algif_aead /bin/false'
sudo rmmod algif_aead 2>/dev/null
```

After applying, the detector should report `Precondition not met` and exit 0.
