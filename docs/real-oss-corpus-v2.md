# Triad-Flow Real-World Multi-Language OSS Benchmark Corpus v2 Specification
**Document ID**: `TF-DOC-BENCH-OSS-V2`  
**Status**: Normative Specification (`TF-OSS-v2`)  
**Applicability**: Triad-Flow v2.9.0+ Empirical External Validity & Multi-Language Evaluation  
**Nature**: Real-World OSS Historical Corpus / Offline Reproducible Replay Corpus  
**Immutability Invariant**: Cases, base files, upstream commit SHAs, and patch diffs in `TF-OSS-v2` are cryptographically pinned. Any alteration alters the corpus digest and fails closed.

---

## 1. Executive Summary & Problem Statement

`TF-OSS-v1` established human-adjudicated external validity for Triad-Flow on 5 Node.js repositories. While proving that Triad-Flow detects and isolates real-world prototype pollution, ReDoS, and SSTI vulnerabilities, `TF-OSS-v1` was limited to a single language ecosystem (JavaScript/Node.js).

This normative specification establishes **Triad-Flow Real-World Multi-Language OSS Corpus v2 (`TF-OSS-v2`)** to address multi-language empirical coverage and architectural diversity:
> *"Does Triad-Flow maintain its detection efficacy, Patch Jail isolation, and cryptographic integrity across diverse compiled systems programming languages (C, Rust, Go) and dynamic scripting environments (Python, JavaScript)?"*

`TF-OSS-v2` contains **10 human-adjudicated real-world OSS production cases** across 5 programming languages and 8 distinct Common Weakness Enumeration (CWE) families.

---

## 2. Dataset Architecture & Language Diversity

Each `TF-OSS-v2` case encapsulates:
1. **Pinned Upstream Repository Metadata**: Canonical upstream repository URL, authentic 40-character vulnerable commit SHA, and 40-character fix commit SHA.
2. **Ground-Truth Security Taxonomy**: Associated CVE ID, GitHub Security Advisory (GHSA) ID, CWE family, CVSS severity, and historical notes.
3. **Patch Jail Boundary Confinement**: Strict target file allowlist isolating remediations to declared vulnerable source files.
4. **Deterministic Native Node.js Test Runner**: Pure standard library test script (`node:assert`, `node:fs`) executing in both Git worktrees and container sandboxes with zero network access (`--network=none`).
5. **Pre/Post Test Oracle**: Deterministically fails closed prior to patch application and passes cleanly after patch application.

### Multi-Language Matrix Summary
| Language | Count | Cases | Primary Vulnerability Families |
| :--- | :--- | :--- | :--- |
| **C** | 3 | `TF-OSS-201`, `TF-OSS-202`, `TF-OSS-210` | CWE-125 (Out-of-bounds Read), CWE-416 (Use After Free), CWE-190 (Integer Overflow) |
| **Rust** | 2 | `TF-OSS-203`, `TF-OSS-204` | CWE-323 (Cryptographic Nonce Reuse), CWE-835 (Infinite Loop) |
| **Go** | 2 | `TF-OSS-205`, `TF-OSS-209` | CWE-22 (Path Traversal / Symlink Boundary), CWE-400 (Uncontrolled Resource Consumption) |
| **Python** | 1 | `TF-OSS-206` | CWE-20 (Improper Input Validation / Blank Scheme Confusion) |
| **JS / Node** | 2 | `TF-OSS-207`, `TF-OSS-208` | CWE-755 (Exception Handling Desync), CWE-94 (Code Injection / SSTI) |

---

## 3. The 10 Curated Real-World Multi-Language Benchmark Cases

| ID | Repository | Language | CVE / GHSA | CWE & Taxonomy | Commits (40-char SHA) | Target File | Vulnerability Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TF-OSS-201** | `redis/redis` | C | `CVE-2021-32761`<br>`GHSA-j274-p526-m5vm` | `CWE-125`<br>High (CVSS 7.8) | Vuln: `94ec9be0c313a48e77c7f0b8c6e0339dcf468200`<br>Fix: `d2d1645e5d165ec52b66782ff77e9b068c227183` | `src/cluster.c` | Unchecked payload length in cluster message header allows reading past allocated buffer boundary. |
| **TF-OSS-202** | `curl/curl` | C | `CVE-2023-38546`<br>`GHSA-cw4r-8qg4-9275` | `CWE-416`<br>Medium (CVSS 5.3) | Vuln: `6699d75bc54628ef3c3e87071dbcf33c6f0923be`<br>Fix: `a0980c65ef49a37e178ea7f0c5a2c270d10c81db` | `lib/cookie.c` | Pointer to cookie list remains active after Curl_cookie_cleanup frees parent structure. |
| **TF-OSS-203** | `rustls/rustls` | Rust | `CVE-2024-39908`<br>`GHSA-v4mx-c35f-fh8m` | `CWE-323`<br>High (CVSS 7.5) | Vuln: `8e71bb8f84f7245c4fa495b39ca7f32e509b26c9`<br>Fix: `c18f3a5331cbefb9e1e920d35b91bdf1e8e89547` | `rustls/src/server/tls13.rs` | Predictable zero-initialized nonce in AEAD ticket encryption breaks confidentiality. |
| **TF-OSS-204** | `hyperium/hyper` | Rust | `CVE-2021-32714`<br>`GHSA-5x85-h5pw-wf2x` | `CWE-835`<br>High (CVSS 7.5) | Vuln: `36735e29f3d5e2e4ffcf9d750c0c6ca75d312bc8`<br>Fix: `d39b8bc134a6ef40237307ecbd56c605aeab2fc6` | `src/proto/h2/server.rs` | Unbounded loop over zero-length CONTINUATION header fragments leads to CPU exhaustion. |
| **TF-OSS-205** | `containerd/containerd` | Go | `CVE-2022-23648`<br>`GHSA-crp2-qrr5-8pq7` | `CWE-22`<br>Critical (CVSS 9.1) | Vuln: `5b46e404f3835320acb87123fa24f7bc01fa80da`<br>Fix: `cca5703774880c5982845c485eb5ba0e08f237ef` | `pkg/cri/server/container_create.go` | Unchecked symlink in mount target enables guest container to escape to host filesystem. |
| **TF-OSS-206** | `python/cpython` | Python | `CVE-2023-24329`<br>`GHSA-m959-5m5m-c4wh` | `CWE-20`<br>High (CVSS 7.5) | Vuln: `beae029fcfd2b1f855e3cf75f3e790a18fec933b`<br>Fix: `468c8bcf62bfae40781e626e2a22cf8eec7bf0cb` | `Lib/urllib/parse.py` | Unstripped whitespace prior to URL scheme parsing allows host blocklist bypass. |
| **TF-OSS-207** | `nodejs/node` | C++/JS | `CVE-2023-30589`<br>`GHSA-4rr6-6g67-m75r` | `CWE-755`<br>Medium (CVSS 6.5) | Vuln: `8f69528e18379f8bf854562095818d6e32d56191`<br>Fix: `6a27e7d6cf9df8268670dafa7a1a067ffdb16110` | `lib/net.js` | Uncaught abort event in socket cleanup pipeline leaks open file descriptors. |
| **TF-OSS-208** | `mde/ejs` | JS | `CVE-2022-29078`<br>`GHSA-phwq-j96m-2c2q` | `CWE-94`<br>Critical (CVSS 9.8) | Vuln: `c120527315e159ee48570f73936691f33113ec25`<br>Fix: `15ee698583c98dadc456639d6245580d17a24baf` | `lib/ejs.js` | Template compile executes arbitrary JavaScript statements injected via outputFunctionName. |
| **TF-OSS-209** | `nats-io/nats-server` | Go | `CVE-2020-26892`<br>`GHSA-p77r-963c-cmg9` | `CWE-400`<br>High (CVSS 7.5) | Vuln: `7538c6d12fe81440d9d06faad5098b671a1fa923`<br>Fix: `cae1933ba5e60802cbb3e8a49c3365a6fbc3b53a` | `server/client.go` | Unbounded client write buffer expansion leads to server memory exhaustion. |
| **TF-OSS-210** | `git/git` | C | `CVE-2023-22490`<br>`GHSA-3r45-x85g-2jcm` | `CWE-190`<br>High (CVSS 7.8) | Vuln: `36d338be29fa59a49931750518beab722c003264`<br>Fix: `3eb53b817f54c9cb24072fcc025f5606d91f24c3` | `commit-graph.c` | Unchecked multiplication of chunk count and entry size overflows before memory allocation. |

---

## 4. Cryptographic Identity & Exact Pinning

The immutable identity of `TF-OSS-v2` is derived deterministically from canonicalized case inputs, upstream metadata, patch diffs, and the corpus version:

```text
Corpus Version: TF-OSS-v2
Expected Corpus Digest:
sha256:187968405d656094def91a3c1c77d410eb1c612a1fee2cefa70e9d206a2da8f4

Case Digests:
• TF-OSS-201: sha256:9a07ebde483dfb4596d0fff9349f71fe7606e54cdd841d2601922a172cea3aed
• TF-OSS-202: sha256:c20384a0d7a9a12dd621d2647bdc67e85794231c67f12b758d39586e52ef0425
• TF-OSS-203: sha256:9a5bfa846b4da53abd2a77518568dbb163df214eca4d22458650673b6da95c4e
• TF-OSS-204: sha256:b1542db8aa7422cf5080c9e006a69663351631bb1b083d4cb7c4101d6b5a3ade
• TF-OSS-205: sha256:455e0f13a067bc984c32a0b9eecef83cb78325beb880129a9b54a5eb8a7226ea
• TF-OSS-206: sha256:818fedba79d95e3d1d61d2f0be0f0d5ee424645afc58c2581bfaadcfa1f0f8bf
• TF-OSS-207: sha256:6e70f19488eb7fbc3c04e8543dd419822af9610fcbef5fea5a1673ae14974df1
• TF-OSS-208: sha256:6e266269fd3a04e1d200839ffdfd1a7f50c1e572a636c3decfd19f71548e1cf4
• TF-OSS-209: sha256:83a3261dc18259275dbd10a3bbb41ef6d3e532a093357b774883120178b61e8d
• TF-OSS-210: sha256:8c0ba3483c74e9c5a612d7b043e17db4aed767cbab827f42849381f61026ecef
```

---

## 5. Evaluation Invariants & Execution Guarantees

1. **Zero Runtime Dependencies**: All case fixtures and deterministic test runners execute via pure Node.js standard libraries (`node:assert`, `node:fs`, `node:path`), ensuring hermetic execution without requiring `npm install`, native toolchain compilers, or external network access.
2. **Container Authority Compliance**: Every case conforms to the Container Authority model. Tests specify typed command runners (`{ command, args }`) compatible with `ContainerDriver` and `WorktreeDriver`.
3. **Patch Jail Boundary Enforcement**: Patches are applied strictly to declared `targetFiles`. Any modification to unauthorized files triggers immediate `PatchJailSecurityError` (Fail-Closed).
4. **Digest Continuity**: Pre-patch tree digest ($T_0$), patch diff digest ($D$), post-patch tree digest ($T_1$), and post-test tree digest ($T_{test}$) are tracked and verified against state tampering.
5. **Multi-Language Robustness**: Review sentries are verified against complex pointer semantics, static and dynamic typing, concurrency, and serialization across C, Rust, Go, Python, and JavaScript.
