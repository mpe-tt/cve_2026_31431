# CVE-2026-31431 ("Copy Fail") Detector

Non-destructive detector for the Linux `algif_aead` / `authencesn`
page-cache scratch-write bug disclosed 2026-04-29.

Disclosure writeup: <https://xint.io/blog/copy-fail-linux-distributions>

## Usage

```sh
python3 test_cve_2026_31431.py [--load-module]
```

Requires Python 3.6+. No third-party dependencies.

stdout receives one line indicating the result; all diagnostic output
goes to stderr.

| stdout        | exit code | meaning                                      |
|---------------|-----------|----------------------------------------------|
| `VULNERABLE`  | 2         | page-cache scratch-write confirmed           |
| `NOT VULNERABLE` | 0      | attack vector not reachable on this kernel   |
| `UNKNOWN`     | 125       | `algif_aead` not loaded; re-run with `--load-module` |
| *(none)*      | 1         | test error                                   |

If `algif_aead` is not already loaded, the script prints `UNKNOWN` and
exits 125 by default. Pass `--load-module` to allow the kernel to
autoload it and proceed with detection. If the module was loaded by the
run, a reminder to unload it is printed at the end.

## What it does

1. Checks whether `algif_aead` is loaded (`/sys/module/algif_aead`).
2. Confirms `AF_ALG` and the `authencesn(hmac(sha256),cbc(aes))`
   algorithm are reachable from an unprivileged process.
3. Creates a 4 KiB sentinel file in a temp directory and populates its
   page cache.
4. Sends 8 bytes of AAD inline via `sendmsg`+cmsg with `seqno_lo` set
   to the marker `PWND`, then splices 32 bytes of the sentinel's
   page-cache page into the AF_ALG op socket.
5. Calls `recv()` to drive decryption. The auth check fails with
   `EBADMSG`; the scratch write fires regardless.
6. Re-reads the file (page cache, not disk) and checks for the marker.

The sentinel file is removed on exit. `/etc/passwd`, `/usr/bin/su`, and
all other system files are never opened.

## Mitigation

Until the patched kernel reaches your distro:

```sh
sudo tee /etc/modprobe.d/disable-algif-aead.conf <<<'install algif_aead /bin/false'
sudo rmmod algif_aead 2>/dev/null
```

After applying, the detector should print `NOT VULNERABLE` and exit 0.

The upstream fix reverts in-place AEAD operations to out-of-place,
keeping page-cache pages out of writable scatterlists.

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

## References

- Xint disclosure writeup: <https://xint.io/blog/copy-fail-linux-distributions>
- CVE-2026-31431
