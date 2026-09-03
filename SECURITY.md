# system-design-primer `generate-epub.sh`: Contributor-Controlled Raw HTML/JS Passed Unsanitized into Distributed EPUB Artifacts, with Build-Time Remote Fetch Side Effect (CWE-79 / CWE-116)

Last saved at 2026-09-03

## Asset

donnemartin/system-design-primer (SOURCE_CODE) — repository-root build script `generate-epub.sh` (git blob `a6bfe05b50da634165286363c80931d1093c607b`, git mode `100755`, the only shell script in the repository), master @ `ae9bbd7b02d90b9866215de185217d33f39ab733`. Runtime dependency: pandoc (3.10 in this audit environment; `pandoc --list-extensions=markdown` confirms `+raw_html` is enabled by default).

## Weakness

Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (cwe-79) / Improper Encoding or Escaping of Output (cwe-116)

## Description

> **Version declaration:** This report targets **system-design-primer master @ `ae9bbd7b02d90b9866215de185217d33f39ab733`** ("Fix link for UDP vs TCP (#1153)"), repository-root script `generate-epub.sh`. All code references below were verified line-by-line against the local repository tree. The finding is **code-level confirmed** (source control-flow/data-flow review + toolchain behavior review + archived PoC artifact review); no real reader-runtime reproduction is included in this submission — see Steps To Reproduce for the reproduction path.

### Summary

`generate-epub.sh` is the sole build entry point the maintainer runs locally to generate and distribute EPUB artifacts. Line 9 invokes `pandoc --from=markdown -o $1 <&0` — **the `+raw_html` / `+raw_tex` extensions are not disabled and no post-processing sanitization step exists anywhere in the script**. All content concatenated by line 17 (main `README.md`), lines 19-23 (`solutions/system_design/*/README.md`, only `*template*` and `*__init__.py*` excluded), and line 34 (`README-ja.md` / `README-zh-Hans.md` / `README-zh-TW.md`) is **markdown fully controlled by any contributor via an ordinary pull request**. A contributor therefore only needs to place a raw HTML/JS block (`<script>`, `onerror` event attributes, `javascript:` URIs, `<iframe srcdoc>`, etc.) in any concatenated source; after the maintainer runs `bash generate-epub.sh` once, that raw HTML/JS **passes verbatim into the xhtml chapters of all 4 EPUB3 artifacts** and is distributed with them. In readers that support scripted content documents (calibre viewer, Readium, epub.js-class; EPUB3 permits scripted content-documents per spec), this constitutes an injection execution surface. During parsing, pandoc also issues build-machine-side GETs for remote URLs referenced in the document (the archived PoC captured 5 × `GET /pwned_remote_fetch.png`, UA `pandoc/3.10`) — this build-time fetch side effect is corroborating only; the independent local-file-read/SSRF report does not overlap with this one.

### Finding A: The dangerous sink — `--from=markdown` leaves raw_html enabled, zero sanitization into the EPUB writer

**File:** `generate-epub.sh:9`

```bash
 9:  pandoc --metadata-file=epub-metadata.yaml --metadata=lang:$2 --from=markdown -o $1 <&0
```

Key observations:

- pandoc's `markdown` input format **enables `+raw_html` (and `+raw_tex`) by default** — `pandoc --list-extensions=markdown` in this environment outputs `+raw_html` and `+raw_tex`. Raw HTML blocks are parsed as RawBlock(format=html) and emitted **verbatim by the HTML/EPUB writers, with zero escaping**. Line 9 appends no `-raw_html`/`-raw_tex` suppression and does not use a stricter reader such as `gfm`.
- Line 9 is the **only conversion sink** in the script; the output `$1` is a hardcoded repository-root relative path (`README.epub`, passed at line 25; `README-*.epub`, passed at line 34).
- The 55-line script contains **no sanitize/escape/post-processing step whatsoever**; the only `rm` is line 27 cleaning up the mktemp temp file, unrelated to output content.

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

- The three source groups — main `README.md` (line 17), all `solutions/system_design/*/README.md` (lines 19-23; the filter matches only directory names `*template*`/`*__init__.py*`, with **zero content validation**), and the three translation READMEs (line 34) — are all markdown files any ordinary contributor can modify via PR, with no review/CI interception point (`.github/` contains only `PULL_REQUEST_TEMPLATE.md`; the repository has no GitHub Actions workflows).
- Lines 51-54 trigger 4 pandoc conversions in a single run (README / README-ja / README-zh-Hans / README-zh-TW); the solutions-concatenated build (line 25) additionally proves the line 17→22 concatenation path reaches the same sink.
- The dependency check only verifies that pandoc is executable (lines 38-48) — no version pinning, no input content validation.

### Finding C: Artifact spec surface and injection survival (archived PoC artifact review)

**File:** `workdir/evidence/epub_poc/extract_README/EPUB/content.opf`, `.../EPUB/text/ch001.xhtml`

```xml
<!-- content.opf (archived artifact) -->
<package version="3.0" ...>
```

```html
<!-- ch001.xhtml (archived artifact) — raw HTML survives verbatim -->
<script>document.title="PWN_RAWHTML_SCRIPT";</script>
```

Key observations:

- `content.opf` is `<package version="3.0">` (EPUB3), which permits scripted content-documents at the spec level; embedded JS is spec-relevant for readers supporting script execution.
- In the archived PoC artifacts, `PWN_RAWHTML_SCRIPT` (main README path) and `PWN_SOL_README_SCRIPT` (solutions concatenation path) plus the DIV/ONERROR/JSHREF/IFRAME markers each appear **2× in `README.epub`** (ch001 + ch002), and each translation carries its own script marker — injection markers survive intact in **all 4 artifacts**, with per-item counts in `artifact_markers.txt`; the template-directory control marker is 0 (lines 20-21 filtering works, proving the markers are not environment noise).
- Build-time fetch corroboration: a local HTTP server captured **5 × `GET /pwned_remote_fetch.png`** (UA `pandoc/3.10`, `http_server_access.log`); stderr records pandoc's remote-fetch request details (`redirectCount=10`). The repository's current content contains no `<script>/javascript:/onerror/onload/<iframe>/<embed>` anywhere (full grep) — this is a **mechanistic injection channel** (triggerable by a future contributor PR), not pre-existing poisoned content.

### Differential vs. safe implementations (why this is a script defect, not a pandoc defect)

| Safeguard | Safe implementation available on the same toolchain | What this script actually does |
| --- | --- | --- |
| raw HTML extension | `--from=markdown-raw_html-raw_tex` or a `gfm`-class reader | **Default `markdown` (`+raw_html` enabled)** (line 9) |
| Output sanitization | Post-build sanitization of EPUB xhtml (strip script/event attrs/javascript: URIs/iframe srcdoc) | **No post-processing at all** |
| Input validation | Pre-scan concatenated sources for dangerous markers | **None** (lines 38-48 only check pandoc is executable) |
| Input trust | Declare build inputs untrusted and isolate them | Directly concatenates contributor-controlled files (lines 17-34) |

pandoc behaves per its documented reader semantics for `markdown`; it is the build script that chooses not to tighten the parsing surface and not to sanitize output, so the defect belongs to the `generate-epub.sh` implementation, not to a pandoc version CVE (pandoc 3.10 in this environment has no known CVE relevant to this call surface).

### Versions Verified

| Version | raw_html enabled by default | Concatenated input sources | Zero-sanitization passthrough to sink | Injection survives in artifacts |
| --- | --- | --- | --- | --- |
| system-design-primer master @ `ae9bbd7b` (`generate-epub.sh` blob `a6bfe05b`; pandoc 3.10 verified) | ❌ Line 9 does not suppress | ❌ Main README + solutions + translations (lines 17-34) | ❌ No sanitize/post-processing | ❌ Survives in all 4 archived artifacts |

The vulnerability is present in the audited version. Because the pattern is structural to the script (default reader + zero sanitization), it is expected to affect other recent versions as well; no fix commit was found in the audited tree.

---

## Steps To Reproduce

**Pre-conditions:** Attacker is any contributor able to open a PR against the repository (no special permissions required); victim is the repository maintainer running `bash generate-epub.sh` in the repository root (the script is executable, git mode `100755`); the environment only requires pandoc installed (lines 38-48, the sole dependency check). Secondary victims are readers who open the distributed EPUB artifact (in a reader supporting scripted content-documents).

**Step 1 — deliver the injection payload.** In a PR, place a raw HTML/JS block in any concatenated source (e.g. `README.md` or `solutions/system_design/poc_x/README.md`):

```markdown
<div>PWN_RAWHTML_DIV</div>

<script>document.title="PWN_RAWHTML_SCRIPT";</script>

<img src="http://ATTACKER_HOST/pwned_remote_fetch.png" />

<img src="x.png" onerror="PWN_RAWHTML_ONERROR" />

<a href="javascript:PWN_RAWHTML_JSHREF">click</a>

<iframe srcdoc="&lt;script&gt;PWN_RAWHTML_IFRAME&lt;/script&gt;"></iframe>
```

**Step 2 — maintainer runs the build.** `bash generate-epub.sh`: lines 17/22/34 concatenate the payload into the tmpfile/stdin, and line 9's pandoc parses it with default `+raw_html` — raw HTML blocks pass into the EPUB writer as RawBlock(html), verbatim.

**Step 3 — inspect the artifacts.** Unzip `README.epub`: `EPUB/text/ch001.xhtml` contains the complete `<script>` marker and `ch002.xhtml` contains the solutions-concatenation marker (each appearing 2×); `README-ja.epub` etc. each carry their own markers; `EPUB/content.opf` is `version="3.0"`. The actual results match the expectations above (archived counts in `workdir/evidence/epub_poc/artifact_markers.txt`); the template-directory control marker is 0.

**Step 4 — build-time fetch (side effect).** Observe on a local HTTP server: when pandoc parses `<img src="http://ATTACKER_HOST/pwned_remote_fetch.png">` it issues a `GET` with UA `pandoc/3.10` (5 captures archived, `http_server_access.log`) — proving the build machine contacts contributor-controlled URLs during build. CSS background URLs inside style blocks do not trigger (pandoc does not parse style-block URLs).

**Verification (whitebox logic reproduction):** All five elements close at the source level — ① root cause: line 9 `--from=markdown` leaves `+raw_html` on and the script performs zero sanitization; ② input reachability: the three contributor-controlled concatenation groups at lines 17/19-23/34; ③ privilege precondition: one routine maintainer build; ④ dangerous sink: the line 9 pandoc conversion; ⑤ impact chain: raw HTML/JS passes verbatim into 4 EPUB3 artifacts and is distributed with them. The archived PoC artifacts (`workdir/evidence/epub_poc/`: script archive, marker counts, HTTP server log, build logs, unpacked artifacts) match this derivation item-by-item; the finding is **verified via whitebox logic reproduction**.

---

## Impact

| Aspect | Detail |
| --- | --- |
| **Attack requirement** | An ordinary contributor PR (markdown text) + one routine maintainer build; no account, no special permissions, no user interaction beyond the maintainer's build |
| **Privilege boundary** | Primary impact surface is the maintainer's build machine (build-time outbound fetch); secondary surface is any reader opening the distributed artifact (JS execution surface within the reader process) |
| **Confidentiality** | The build-time fetch leaks the build machine's egress IP and toolchain fingerprint (UA `pandoc/3.10`); reader-side JS can access reader-environment data and make outbound calls |
| **Integrity** | The rendered content and behavior of distributed artifacts are attacker-controlled (forged content, outbound links, script logic); what readers see can be fully altered from the author's intent |
| **Availability** | Malicious reader-side scripts can disrupt a reading session; no direct impact on build-machine availability |
| **Severity** | Medium. CVSS 3.1 `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` ≈ **4.8** — requires one maintainer build and (secondarily) a scripting-enabled reader |
| **CVE eligibility** | Yes. GitHub is a CNA and accepts reports via Private Vulnerability Reporting; the distinct root cause (unsanitized build-script passthrough), publicly reachable attack surface (contributor PRs), and concrete impact (distributed-artifact injection + build-time fetch) meet CVE criteria |
| **Recommended submission channel** | GitHub Private Vulnerability Reporting (https://github.com/donnemartin/system-design-primer/security/advisories/new) — the maintainer receives reports through GitHub's official private flow and a CVE can be assigned; the repository has no SECURITY.md and the README directs contact through the maintainer's GitHub page (https://github.com/donnemartin) |

Additional notes:

- **No overlap with the adjacent findings.** This report's sink is "raw HTML/JS entering the artifact body" (injection execution surface); build-machine local-file-read/SSRF exfiltration and symlink overwrite are independent root causes with their own reports. The build-time remote GET is recorded here only as corroboration of the injection chain.
- **Current repository content is not poisoned.** Existing markdown contains no malicious HTML markers (full scan) — this is a mechanistic injection channel triggerable by a future contributor PR.
- **Suggested fix:** switch line 9 to `--from=markdown-raw_html-raw_tex` (or `gfm`); if some HTML must be kept, sanitize the EPUB xhtml after build (strip script/event attributes/javascript: URIs/iframe srcdoc); document in contributor docs that build inputs are untrusted, and add CI scanning of concatenated sources for dangerous markers.

*This submission was prepared in accordance with the platform Policy and Disclosure Guidelines; verification is whitebox logic reproduction (source level), with archived artifacts as corroboration only.*
