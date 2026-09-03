# system-design-primer `generate-epub.sh`: Unrestricted pandoc Resource Fetching — Build-Machine Local File Read and Blind SSRF with Content Exfiltrated into Publicly Distributed EPUB Artifacts (CWE-200 / CWE-22 / CWE-918)

Last saved at 2026-09-03

## Asset

donnemartin/system-design-primer (SOURCE_CODE) — repository-root build script `generate-epub.sh` (git blob `a6bfe05b50da634165286363c80931d1093c607b`, git mode `100755`), master @ `ae9bbd7b02d90b9866215de185217d33f39ab733`. Runtime dependency: pandoc (3.10 in this audit environment).

## Weakness

Exposure of Sensitive Information to an Unauthorized Actor (cwe-200) / Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') (cwe-22) / Server-Side Request Forgery (SSRF) (cwe-918)

## Description

> **Version declaration:** This report targets **system-design-primer master @ `ae9bbd7b02d90b9866215de185217d33f39ab733`**, repository-root script `generate-epub.sh`. All code references below were verified line-by-line against the local repository tree. The finding is **code-level confirmed** (source control-flow/data-flow review + toolchain resource-fetch semantics review + archived PoC artifact review); no dynamic testing against real external hosts is included in this submission — see Steps To Reproduce for the reproduction path.

### Summary

`generate-epub.sh` hands fully contributor-controlled markdown (main `README.md`, the 3 translation READMEs, `solutions/system_design/*/README.md`) to the line-9 pandoc sink (`pandoc --from=markdown -o $1 <&0`) with **no URL scheme, path, or network validation of any kind**. pandoc's EPUB writer **actively fetches** image/media resources referenced by the document during conversion: `file://` URLs, absolute paths, and `../` relative traversal resolve at the filesystem layer (baseline is the repository root where the maintainer runs the script; `../` escapes the repository), while `http(s)://` URLs are fetched over the network and **302 redirects are followed by default** — no scheme allowlist, no path restriction (chroot), no network kill switch. Two independent exfiltration chains result: **(a)** a contributor places `![x](file:///etc/passwd)`, `![x](/home/maintainer/.ssh/id_rsa)`, or a `../` traversal reference in markdown, and the build machine's (maintainer's workstation) arbitrary readable files are fetched by pandoc and embedded as media entries in the EPUB, distributed with the public artifact; **(b)** a contributor places any http(s) URL (including internal addresses such as `169.254.169.254`), and the build machine issues a GET during build following redirects — blind SSRF probing of internal networks, egress information leakage, and **the internal service response body is likewise embedded into the public artifact**. The archived PoC artifacts show: exfiltrated content from all 4 local-read channels (`file://`, absolute path, `../` traversal, raw HTML `<img file://>`) and both SSRF channels (direct, 302-redirected) was recovered from all 4 artifacts, with 12 build-time outbound request records in total (4×302 + 8×200).

### Finding A: The dangerous sink — pandoc resource fetching with zero restrictions

**File:** `generate-epub.sh:9`

```bash
 9:  pandoc --metadata-file=epub-metadata.yaml --metadata=lang:$2 --from=markdown -o $1 <&0
```

Key observations:

- Line 9 is the **only conversion sink** in the script: contributor-controlled markdown is read from stdin and written as EPUB. The pandoc EPUB writer resolves document-referenced image/media resources via "parse URL → fetch content → write `EPUB/media/fileN.*`", with **no URL scheme allowlist**: `file://`, absolute paths, and `../` relative paths resolve at the filesystem layer (cwd is the repository root where the maintainer runs the script), and `http(s)://` URLs are fetched over the network with redirects followed by default (Haskell http-client default behavior).
- The script contains no resource-fetch controls whatsoever: `--extract-media` is unused, there is no offline flag, no sandbox, no pre-scan of URL schemes in the markdown content; the dependency check (lines 38-48) only verifies pandoc is executable — no version pinning, no parameter to disable resource fetching.

### Finding B: Attacker input reachability — all three concatenation groups are fully contributor-controlled

**File:** `generate-epub.sh:17-34`

```bash
17:  cat ./README.md >> $tmpfile
19:  for dir in ./solutions/system_design/*; do
20:    case $dir in *template*) continue;; esac
21:    case $dir in *__init__.py*) continue;; esac
22:    : [[ -d "$dir" ]] && ( cd "$dir" && cat ./README.md >> $tmpfile && echo "" >> $tmpfile )
23:  done
25:  cat $tmpfile | generate_from_stdin 'README.epub' 'en'
34:  cat $name.md | generate_from_stdin $name.epub $language   # README-ja / README-zh-Hans / README-zh-TW
```

Key observations:

- The main README (line 17), solutions subdirectory READMEs (lines 19-23; only the `*template*`/`*__init__.py*` directory names are excluded, with zero content validation), and translation READMEs (line 34) can all be written to any line by any ordinary contributor via PR; there is no CI/review interception (`.github/` contains only `PULL_REQUEST_TEMPLATE.md`).
- Lines 51-54 trigger 4 pandoc conversions in a single run — **every artifact carries the complete exfiltrated content**.
- Ordinary markdown image syntax `![alt](url)` and raw HTML `<img src>` both reach the resource-fetch path (the latter parsed via the default `+raw_html`).

### Finding C: Exfiltrated content is doubly reachable inside the artifact (archived PoC artifact review)

**File:** `workdir/evidence/ssrf_fileexfil/extract_README/EPUB/media/file0.txt`, `.../text/ch001.xhtml`

```
# EPUB/media/file0.txt (archived artifact, 49 B, sha256 fa623e35…, identical to build-machine canary canary_root.txt)
SECRET_ROOT_LINE:root:x:0:0:root:/root:/bin/bash
```

```html
<!-- ch001.xhtml (archived artifact) — exfiltrated content reachable both in the body and the media directory -->
<embed src="../media/file0.txt" ... />
<img alt="RAWHTML_FILEIMG_CANARY" src="../media/file0.txt" ... />
<img alt="SSRF_DIRECT" src="../media/file3.png" ... />
<img alt="SSRF_REDIRECT" src="../media/file4.png" ... />
```

Key observations:

- The archived `EPUB/media` of all 4 artifacts is identical: `file0.txt` = the `file://` and raw HTML `<img file://>` channels sharing one source (sha256 `fa623e35…`, content `SECRET_ROOT_LINE:root:…`); `file1.txt`/`file2.txt` are the absolute-path and `../`-traversal channels as **independent** entries (sha256 `535bfc6c…`); `file3.png`/`file4.png` are the SSRF direct and 302-redirect channels (sha256 `9b826817…`, content `INTERNAL_SECRET_PNG_CONTENT`). Canary recovery counts: `SECRET_ROOT_LINE` 1×, `SECRET_HOSTNAME_CANARY` 2×, `INTERNAL_SECRET_PNG_CONTENT` 2×, identical per artifact (`canary_recovery.txt`, `media_listing.txt`).
- Build-machine outbound requests captured: **12 records** — 4×`GET /redirect1 302` + 8×`GET /internal_secret.png 200` (each EPUB build produces one "redirect + double GET" group), proving the redirect chain is followed (`http_server_access.log`, `http_requests_evidence.txt`).
- The body references prove exfiltrated content is **doubly reachable in the artifact** — `<img>/<embed>` in the chapter body and the media directory — extractable by any reader who unzips the container; fetched content never stays on the build machine but ships with the artifact.

### Differential vs. safe implementations (why this is a script defect, not a pandoc defect)

| Safeguard | Safe implementation available on the same toolchain | What this script actually does |
| --- | --- | --- |
| URL scheme allowlist | Pre-scan concatenated sources; allow only in-repo relative paths / necessary CDNs | **No pre-scan at all** |
| Path restriction | Normalize and confine within the repository root | `../` traversal, `file://`, and absolute paths all resolve (cwd baseline) |
| Network isolation | CI-isolated network / fixed proxy / redirect following disabled | Build machine fetches directly; 302 chains are followed |
| Output audit | Audit EPUB media entries before release | None |

pandoc's resource fetching is its documented EPUB-writer behavior; it is the build script that applies no scheme/path/network constraint to untrusted input, so the defect belongs to the `generate-epub.sh` implementation.

### Versions Verified

| Version | Scheme allowlist on resource fetch | Path restriction | Redirect/network restriction | Local-read + SSRF content ships in artifacts |
| --- | --- | --- | --- | --- |
| system-design-primer master @ `ae9bbd7b` (`generate-epub.sh` blob `a6bfe05b`; pandoc 3.10) | ❌ None | ❌ None (`file://`, absolute, `../` all reachable) | ❌ None (302 followed) | ❌ Exfiltrated content recovered from all 6 channels in all 4 artifacts |

The vulnerability is present in the audited version. Because the pattern is structural to the script (zero resource-fetch constraints), it is expected to affect other recent versions as well; no fix commit was found in the audited tree.

---

## Steps To Reproduce

**Pre-conditions:** Attacker is any contributor able to open a PR (plain text content suffices — no special git capabilities needed); victim is the maintainer running `bash generate-epub.sh` in the repository root (git mode `100755`); the environment only requires pandoc installed. An "internal-only service" can be simulated on loopback (the archived PoC used `127.0.0.1:18099`; no real external host was contacted).

**Step 1 — deliver the multi-channel payload.** In a PR, place the following in any concatenated source (archived verbatim in `payload_README.md`):

```markdown
![FILEURL_CANARY](file:///home/maintainer/secret_root.txt)

![ABSPATH_CANARY](/home/maintainer/secret_host.txt)

![TRAVERSAL_CANARY](../../../../outside/secret_host.txt)

<img src="file:///home/maintainer/secret_root.txt" alt="RAWHTML_FILEIMG_CANARY" />

![SSRF_DIRECT](http://127.0.0.1:18099/internal_secret.png)

![SSRF_REDIRECT](http://127.0.0.1:18099/redirect1)
```

**Step 2 — maintainer runs the build.** `bash generate-epub.sh`: lines 17/22/34 concatenate the payload → line 9's pandoc resolves each resource reference during conversion → local paths resolve via the filesystem (`../` traverses upward from the repository-root cwd) and http(s) URLs are fetched with 302 redirects followed.

**Step 3 — inspect the artifact media entries.** Unzip all 4 EPUBs: `EPUB/media/` contains `file0.txt` (the `file://` channel, with `SECRET_ROOT_LINE:root:x:0:0:…`), `file1.txt`+`file2.txt` (the absolute-path and `../`-traversal channels as two independent entries), and `file3.png`+`file4.png` (SSRF direct and 302-redirect, content `INTERNAL_SECRET_PNG_CONTENT`). Actual results: all 4 artifacts identical, all 3 canaries recovered (`SECRET_ROOT_LINE` 1×, `SECRET_HOSTNAME_CANARY` 2×, `INTERNAL_SECRET_PNG_CONTENT` 2×).

**Step 4 — inspect the body references and outbound requests.** `EPUB/text/ch001.xhtml` shows `<embed src="../media/fileN.txt">` (lines 16/20/24), `<img alt="RAWHTML_FILEIMG_CANARY" src="../media/file0.txt">` (line 27), and `<img alt="SSRF_DIRECT/SSRF_REDIRECT" src="../media/file3/4.png">` (lines 29/32); the loopback server access log records 4×`GET /redirect1 302` + 8×`GET /internal_secret.png 200` — the redirect chain is followed by pandoc.

**Verification (whitebox logic reproduction):** All five elements close at the source level — ① root cause: line 9's pandoc resource fetching with no scheme/path/network restriction and zero hardening in the script; ② input reachability: resource references in contributor-controlled markdown at lines 17/19-23/34; ③ privilege precondition: one routine maintainer build; ④ dangerous sink: conversion-time resource fetching at line 9 (filesystem read + network request); ⑤ impact chain: arbitrary build-machine readable files and internal service response bodies embedded into `EPUB/media` and body references, publicly distributed with all 4 artifacts. The archived PoC artifacts (`workdir/evidence/ssrf_fileexfil/`: script, payload verbatim, canary originals with sha256, recovery counts, media listing, outbound-request logs, build logs, unpacked artifacts) match this derivation item-by-item; the finding is **verified via whitebox logic reproduction**.

---

## Impact

| Aspect | Detail |
| --- | --- |
| **Attack requirement** | An ordinary contributor PR (plain markdown text) + one routine maintainer build; no account, no special permissions, no special git objects such as symlinks |
| **Privilege boundary** | The contributor gains indirect control over file reads and outbound requests on the maintainer's build machine; affected data leaves the build machine inside a **public** artifact, extractable by any downloader |
| **Confidentiality** | Arbitrary build-machine readable files (e.g. `~/.ssh/id_rsa`, credential files, `/etc/passwd`) are persistently embedded into a public artifact; the response bodies of internal-only services are likewise carried back into the public artifact; build-time requests leak the build machine's egress IP and internal liveness/port information |
| **Integrity** | No direct integrity impact (read + request oriented); attacker-injected media pollutes artifact content as a secondary integrity effect |
| **Availability** | No direct impact |
| **Severity** | High (low end). CVSS 3.1 `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` ≈ **6.8** — read content crosses the trust boundary into a publicly distributed artifact, but triggering requires one maintainer build |
| **CVE eligibility** | Yes. GitHub is a CNA and accepts reports via Private Vulnerability Reporting; the distinct root cause (unconstrained resource fetching), publicly reachable attack surface (contributor PRs), and concrete impact (build-machine file exfiltration + blind SSRF response exfiltration) meet CVE criteria |
| **Recommended submission channel** | GitHub Private Vulnerability Reporting (https://github.com/donnemartin/system-design-primer/security/advisories/new) — the official private flow with CVE assignment; the repository has no SECURITY.md and the README directs contact through the maintainer's GitHub page (https://github.com/donnemartin) |

Additional notes:

- **Blind-SSRF characteristic.** The build process does not echo response content back to the contributor; the direct return channel is "response body embedded into the public EPUB" — more severe than pure blind SSRF (internal data is recoverable by any artifact downloader). Build-machine egress information is obtained out-of-band via an attacker-controlled server.
- **Redirect following enlarges the attack surface.** 302 chains can bypass simple first-hop URL filtering and steer the build machine to arbitrary targets.
- **No overlap with the adjacent findings.** This report does not depend on git mode 120000 symlink delivery (the symlink mechanism has its own report); it shares the "contributor content enters the build" precondition with the raw-HTML injection report but the dangerous sink differs (resource fetching vs. artifact-body injection).
- **Suggested fix:** tighten the parsing surface with `--from=markdown-raw_html-raw_tex`; pre-scan concatenated sources for resource references and reject local paths/internal addresses (scheme allowlist + path normalization confined to the repository root); where network resources are genuinely needed, use a fixed proxy with redirect following disabled or a CI-isolated network; audit EPUB media entries before release.

*This submission was prepared in accordance with the platform Policy and Disclosure Guidelines; verification is whitebox logic reproduction (source level), with archived artifacts as corroboration only.*
