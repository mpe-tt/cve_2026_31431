# CVE-2026-31431 ("Copy Fail") Toolkit

Detector and proof-of-concept LPE for the Linux `algif_aead` /
`authencesn` page-cache scratch-write bug disclosed 2026-04-29.

Disclosure writeup: <https://xint.io/blog/copy-fail-linux-distributions>

## Authorization

Use only on hosts you own or are explicitly engaged to assess. The LPE
modifies in-memory state (page cache) but the technique is real
privilege escalation — running it on systems without authorization is
illegal in most jurisdictions.

## Vulnerability summary

`algif_aead` runs AEAD operations in-place (`req->src == req->dst`).
When the source data is fed in via `splice()` from a regular file, the
destination scatterlist contains references to the file's page-cache
pages — i.e. the kernel will write into them. The
`authencesn(hmac(sha256), cbc(aes))` algorithm then performs a 4-byte
"scratch" write of the AAD's `seqno_lo` field (bytes 4–7 of the
sendmsg-supplied AAD) into that destination, corrupting the page-cache
copy of the file.

Because the on-disk file is never modified, there is no on-disk
signature; the corruption is observed only by readers that share the
page cache. `/etc/passwd` and `/usr/bin/su` are both world-readable, so
an unprivileged local user can corrupt the running kernel's view of
either.

Affected: kernels carrying commit `72548b093ee3` (in-place AEAD, 2017)
without the upstream revert. The disclosure confirmed Ubuntu 24.04 LTS,
Amazon Linux 2023, RHEL 14.3, and SUSE 16, but the underlying primitive
predates that range.

## Files

| File | Purpose |
| --- | --- |
| `test_cve_2026_31431.py` | Non-destructive detector. Operates on a sentinel file in a temp dir; never touches system binaries. |

Both scripts are pure Python 3.10+ stdlib.

## Quick start

```sh
# 1. Detect
python3 test_cve_2026_31431.py
#   exit 0 = not vulnerable, 2 = vulnerable, 1 = test error
```

## Detector usage

```
python3 test_cve_2026_31431.py
```

What it does:

1. Confirms `AF_ALG` and the `authencesn(hmac(sha256),cbc(aes))`
   algorithm are reachable from an unprivileged process.
2. Creates a 4 KiB sentinel file in a temp directory, populates the
   page cache.
3. Sends 8 bytes of AAD inline via `sendmsg`+cmsg with seqno_lo set to
   the marker `PWND`, then `os.splice()`s 32 bytes of the sentinel's
   page-cache page into the AF_ALG op socket.
4. Calls `recv()` to drive decryption. The auth check fails with
   `EBADMSG`; the scratch write fires regardless.
5. Re-reads the file (page cache, not disk) and looks for the marker.

Output classes:

- `Precondition not met` — `AF_ALG` or `authencesn` unavailable. Exit 0.
- `VULNERABLE to CVE-2026-31431` — marker `PWND` landed in the spliced
  page. Exit 2.
- `Page cache MODIFIED via in-place AEAD splice path` — the page was
  written to but the marker did not land at the expected position.
  Treat as vulnerable. Exit 2.
- `Page cache intact` — patched. Exit 0.

The detector never touches `/usr/bin/su`, `/etc/passwd`, or any other
file outside the temp directory it creates, and that file is removed on
exit.

## How `write4` works

```
sendmsg([8-byte AAD], cmsg=[ALG_SET_OP=DECRYPT, ALG_SET_IV, ALG_SET_AEAD_ASSOCLEN=8],
        flags=MSG_MORE)
splice(target_fd, pipe_w, 32, offset_src=file_offset)
splice(pipe_r, op_fd, 32)
recv(op_fd)   # EBADMSG; scratch write has already landed
```

The 4 bytes from AAD positions 4–7 (`seqno_lo`) are written by
`authencesn` into the destination scatterlist, which on this code path
is the page-cache page we spliced from `target_fd`. The landing offset
within the page corresponds to the `offset_src` we passed to `splice()`.

## Mitigation

Until the patched kernel reaches your distro:

```sh
sudo tee /etc/modprobe.d/disable-algif-aead.conf <<<'install algif_aead /bin/false'
sudo rmmod algif_aead 2>/dev/null
```

After applying, `test_cve_2026_31431.py` should report `Precondition
not met` and exit 0.

The upstream fix reverts in-place AEAD operations to out-of-place,
keeping page-cache pages out of writable scatterlists.

## References

- Xint disclosure writeup: <https://xint.io/blog/copy-fail-linux-distributions>
- CVE-2026-31431
