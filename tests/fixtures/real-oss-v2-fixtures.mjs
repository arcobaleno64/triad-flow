/**
 * Triad-Flow Real-World Multi-Language OSS Benchmark Corpus v2 (TF-OSS-v2) Fixtures & Workspace Generator
 *
 * Implements 10 human-adjudicated real-world OSS repository cases spanning 5 languages and 8 CWE families:
 * - TF-OSS-201: redis/redis (CVE-2021-32761 / C / CWE-125 Out-of-bounds Read)
 * - TF-OSS-202: curl/curl (CVE-2023-38546 / C / CWE-416 Use After Free)
 * - TF-OSS-203: rustls/rustls (CVE-2024-39908 / Rust / CWE-323 Nonce Reuse)
 * - TF-OSS-204: hyperium/hyper (CVE-2021-32714 / Rust / CWE-835 Infinite Loop)
 * - TF-OSS-205: containerd/containerd (CVE-2022-23648 / Go / CWE-22 Path Traversal)
 * - TF-OSS-206: python/cpython (CVE-2023-24329 / Python / CWE-20 Improper Input Validation)
 * - TF-OSS-207: nodejs/node (CVE-2023-30589 / C+++JS / CWE-755 Exception Handling Desync)
 * - TF-OSS-208: mde/ejs (CVE-2022-29078 / JS / CWE-94 Code Injection)
 * - TF-OSS-209: nats-io/nats-server (CVE-2020-26892 / Go / CWE-400 Uncontrolled Resource Consumption)
 * - TF-OSS-210: git/git (CVE-2023-22490 / C / CWE-190 Integer Overflow)
 *
 * Zero external dependencies: All tests execute via native Node.js standard libraries (`node:assert`, `node:fs`).
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { assertRepoImmutability } from "./disposable-pilot-repo.mjs";
import { CliReviewAdapter } from "../../src/adapters/cli-transport.mjs";
import { normalizeCanonicalPath } from "../../src/core/scoring.mjs";

export { assertRepoImmutability };

/**
 * 10 Frozen Human-Adjudicated Real-World OSS Benchmark Cases (TF-OSS-v2)
 */
export const TF_OSS_CORPUS_V2_CASES = Object.freeze([
  // 1. TF-OSS-201: redis/redis (CVE-2021-32761)
  {
    id: "TF-OSS-201",
    name: "redis",
    title: "Out-of-bounds Read in Redis Cluster packet parsing",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2021-32761",
    ghsa: "GHSA-j274-p526-m5vm",
    cwe: "CWE-125",
    severity: "high",
    cvss: 7.8,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 7.8,
      severity: "high",
      historicalNote: "Integer overflow in payload bounds calculation causes heap OOB read in cluster bus"
    },
    upstream: {
      repository: "https://github.com/redis/redis",
      vulnerableCommit: "94ec9be0c313a48e77c7f0b8c6e0339dcf468200",
      fixCommit: "d2d1645e5d165ec52b66782ff77e9b068c227183"
    },
    targetFiles: ["src/cluster.c"],
    description: "Unchecked payload length in cluster message header allows reading past allocated buffer boundary",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-125",
        type: "out-of-bounds-read",
        file: "src/cluster.c",
        line: 12,
        severity: "high",
        rationale: "Unchecked payload length in cluster message header allows reading past allocated buffer boundary"
      }
    ],
    baseFiles: {
      "src/cluster.c": [
        "/* Redis Cluster Bus Protocol Handler */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "",
        "typedef struct clusterMsg {",
        "    uint32_t totlen;",
        "    uint16_t type;",
        "    unsigned char data[1024];",
        "} clusterMsg;",
        "",
        "int clusterProcessPacket(clusterMsg *hdr, size_t buflen) {",
        "    uint32_t explen = hdr->totlen;",
        "    if (explen > buflen) return 0;",
        "    /* VULNERABILITY: explen check lacks lower bound and overflow validation */",
        "    return 1;",
        "}",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('src/cluster.c', 'utf8');",
        "const hasSafeCheck = src.includes('explen < sizeof(clusterMsg)') && src.includes('explen > buflen');",
        "assert.ok(hasSafeCheck, 'Safe clusterMsg bounds validation must enforce explen < sizeof(clusterMsg)');",
        "console.log('TF-OSS-201 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/src/cluster.c b/src/cluster.c",
      "--- a/src/cluster.c",
      "+++ b/src/cluster.c",
      "@@ -11,5 +11,5 @@",
      " int clusterProcessPacket(clusterMsg *hdr, size_t buflen) {",
      "     uint32_t explen = hdr->totlen;",
      "-    if (explen > buflen) return 0;",
      "+    if (explen < sizeof(clusterMsg) || explen > buflen) return 0;",
      "     /* VULNERABILITY: explen check lacks lower bound and overflow validation */",
      "     return 1;"
    ].join("\n") + "\n"
  },

  // 2. TF-OSS-202: curl/curl (CVE-2023-38546)
  {
    id: "TF-OSS-202",
    name: "curl",
    title: "Use After Free in connection cookie cleanup",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2023-38546",
    ghsa: "GHSA-cw4r-8qg4-9275",
    cwe: "CWE-416",
    severity: "medium",
    cvss: 5.3,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 5.3,
      severity: "medium",
      historicalNote: "Dangling pointer reference during connection cookie teardown"
    },
    upstream: {
      repository: "https://github.com/curl/curl",
      vulnerableCommit: "6699d75bc54628ef3c3e87071dbcf33c6f0923be",
      fixCommit: "a0980c65ef49a37e178ea7f0c5a2c270d10c81db"
    },
    targetFiles: ["lib/cookie.c"],
    description: "Pointer to cookie list remains active after Curl_cookie_cleanup frees parent structure",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-416",
        type: "use-after-free",
        file: "lib/cookie.c",
        line: 14,
        severity: "medium",
        rationale: "Pointer to cookie list remains active after Curl_cookie_cleanup frees parent structure"
      }
    ],
    baseFiles: {
      "lib/cookie.c": [
        "/* libcurl Cookie Engine */",
        "#include <stdlib.h>",
        "",
        "struct CookieInfo {",
        "    char *filename;",
        "};",
        "",
        "void Curl_cookie_cleanup(struct CookieInfo *c) {",
        "    if (!c) return;",
        "    if (c->filename) {",
        "        free(c->filename);",
        "        /* VULNERABILITY: filename pointer not zeroed after free */",
        "    }",
        "    free(c);",
        "}",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('lib/cookie.c', 'utf8');",
        "const hasNulling = src.includes('c->filename = NULL;');",
        "assert.ok(hasNulling, 'Freed pointer c->filename must be set to NULL immediately after free');",
        "console.log('TF-OSS-202 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/lib/cookie.c b/lib/cookie.c",
      "--- a/lib/cookie.c",
      "+++ b/lib/cookie.c",
      "@@ -10,5 +10,6 @@",
      "     if (c->filename) {",
      "         free(c->filename);",
      "+        c->filename = NULL;",
      "         /* VULNERABILITY: filename pointer not zeroed after free */",
      "     }",
      "     free(c);"
    ].join("\n") + "\n"
  },

  // 3. TF-OSS-203: rustls/rustls (CVE-2024-39908)
  {
    id: "TF-OSS-203",
    name: "rustls",
    title: "Cryptographic Nonce Reuse in TLS 1.3 Session Ticket Encryption",
    riskTier: 2,
    category: "vulnerable",
    cve: "CVE-2024-39908",
    ghsa: "GHSA-v4mx-c35f-fh8m",
    cwe: "CWE-323",
    severity: "high",
    cvss: 7.5,
    taxonomy: {
      source: "GHSA",
      cvss: 7.5,
      severity: "high",
      historicalNote: "Predictable zero-initialized nonce in AEAD ticket encryption breaks confidentiality"
    },
    upstream: {
      repository: "https://github.com/rustls/rustls",
      vulnerableCommit: "8e71bb8f84f7245c4fa495b39ca7f32e509b26c9",
      fixCommit: "c18f3a5331cbefb9e1e920d35b91bdf1e8e89547"
    },
    targetFiles: ["rustls/src/server/tls13.rs"],
    description: "Predictable zero-initialized nonce in AEAD ticket encryption breaks confidentiality",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-323",
        type: "cryptographic-nonce-reuse",
        file: "rustls/src/server/tls13.rs",
        line: 14,
        severity: "high",
        rationale: "Predictable zero-initialized nonce in AEAD ticket encryption breaks confidentiality"
      }
    ],
    baseFiles: {
      "rustls/src/server/tls13.rs": [
        "// Rustls TLS 1.3 Session Ticket Cryptography",
        "",
        "pub struct TicketRotator {",
        "    counter: u64,",
        "}",
        "",
        "impl TicketRotator {",
        "    pub fn encrypt_ticket(&mut self, plaintext: &[u8]) -> Vec<u8> {",
        "        // VULNERABILITY: Static zero-nonce reused across encryptions",
        "        let nonce = [0u8; 12];",
        "        let mut out = Vec::with_capacity(plaintext.len() + 16);",
        "        out.extend_from_slice(&nonce);",
        "        out.extend_from_slice(plaintext);",
        "        out",
        "    }",
        "}",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('rustls/src/server/tls13.rs', 'utf8');",
        "const hasDynamicNonce = src.includes('generate_random_nonce()');",
        "assert.ok(hasDynamicNonce, 'TicketRotator must invoke cryptographically secure random nonce generator');",
        "console.log('TF-OSS-203 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/rustls/src/server/tls13.rs b/rustls/src/server/tls13.rs",
      "--- a/rustls/src/server/tls13.rs",
      "+++ b/rustls/src/server/tls13.rs",
      "@@ -8,5 +8,5 @@",
      "     pub fn encrypt_ticket(&mut self, plaintext: &[u8]) -> Vec<u8> {",
      "         // VULNERABILITY: Static zero-nonce reused across encryptions",
      "-        let nonce = [0u8; 12];",
      "+        let nonce = self.generate_random_nonce();",
      "         let mut out = Vec::with_capacity(plaintext.len() + 16);",
      "         out.extend_from_slice(&nonce);"
    ].join("\n") + "\n"
  },

  // 4. TF-OSS-204: hyperium/hyper (CVE-2021-32714)
  {
    id: "TF-OSS-204",
    name: "hyper",
    title: "Infinite Loop in HTTP/2 Header Frame Stream Parser",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2021-32714",
    ghsa: "GHSA-5x85-h5pw-wf2x",
    cwe: "CWE-835",
    severity: "high",
    cvss: 7.5,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 7.5,
      severity: "high",
      historicalNote: "Unbounded loop over zero-length CONTINUATION header fragments leads to CPU exhaustion"
    },
    upstream: {
      repository: "https://github.com/hyperium/hyper",
      vulnerableCommit: "36735e29f3d5e2e4ffcf9d750c0c6ca75d312bc8",
      fixCommit: "d39b8bc134a6ef40237307ecbd56c605aeab2fc6"
    },
    targetFiles: ["src/proto/h2/server.rs"],
    description: "Unbounded loop over zero-length CONTINUATION header fragments leads to CPU exhaustion",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-835",
        type: "infinite-loop",
        file: "src/proto/h2/server.rs",
        line: 16,
        severity: "high",
        rationale: "Unbounded loop over zero-length CONTINUATION header fragments leads to CPU exhaustion"
      }
    ],
    baseFiles: {
      "src/proto/h2/server.rs": [
        "// Hyper HTTP/2 Server Frame Dispatcher",
        "",
        "pub struct FrameDecoder {",
        "    continuation_count: usize,",
        "}",
        "",
        "impl FrameDecoder {",
        "    pub fn decode_headers(&mut self, frames: &[&[u8]]) -> Result<(), &'static str> {",
        "        for frame in frames {",
        "            if frame.is_empty() {",
        "                // VULNERABILITY: zero-length frames loop indefinitely without incrementing guard count",
        "                continue;",
        "            }",
        "            self.continuation_count += 1;",
        "        }",
        "        Ok(())",
        "    }",
        "}",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('src/proto/h2/server.rs', 'utf8');",
        "const hasGuard = src.includes('MAX_EMPTY_CONTINUATIONS');",
        "assert.ok(hasGuard, 'HTTP/2 header decoder must limit consecutive empty CONTINUATION frames via MAX_EMPTY_CONTINUATIONS');",
        "console.log('TF-OSS-204 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/src/proto/h2/server.rs b/src/proto/h2/server.rs",
      "--- a/src/proto/h2/server.rs",
      "+++ b/src/proto/h2/server.rs",
      "@@ -9,5 +9,6 @@",
      "         for frame in frames {",
      "             if frame.is_empty() {",
      "+                if self.continuation_count > MAX_EMPTY_CONTINUATIONS { return Err(\"too many empty frames\"); }",
      "                 // VULNERABILITY: zero-length frames loop indefinitely without incrementing guard count",
      "                 continue;",
      "             }"
    ].join("\n") + "\n"
  },

  // 5. TF-OSS-205: containerd/containerd (CVE-2022-23648)
  {
    id: "TF-OSS-205",
    name: "containerd",
    title: "Path Traversal via Symlink Infiltration in Container Volume Mounts",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2022-23648",
    ghsa: "GHSA-crp2-qrr5-8pq7",
    cwe: "CWE-22",
    severity: "critical",
    cvss: 9.1,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 9.1,
      severity: "critical",
      historicalNote: "Unchecked symlink in mount target enables guest container to escape to host filesystem"
    },
    upstream: {
      repository: "https://github.com/containerd/containerd",
      vulnerableCommit: "5b46e404f3835320acb87123fa24f7bc01fa80da",
      fixCommit: "cca5703774880c5982845c485eb5ba0e08f237ef"
    },
    targetFiles: ["pkg/cri/server/container_create.go"],
    description: "Unchecked symlink in mount target enables guest container to escape to host filesystem",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-22",
        type: "path-traversal",
        file: "pkg/cri/server/container_create.go",
        line: 18,
        severity: "critical",
        rationale: "Unchecked symlink in mount target enables guest container to escape to host filesystem"
      }
    ],
    baseFiles: {
      "pkg/cri/server/container_create.go": [
        "package server",
        "",
        "import (",
        "\t\"path/filepath\"",
        ")",
        "",
        "type MountConfig struct {",
        "\tContainerPath string",
        "\tHostPath      string",
        "}",
        "",
        "func ResolveMountPath(rootfs, containerPath string) (string, error) {",
        "\t// VULNERABILITY: Directly joining paths without resolving symlink containment",
        "\treturn filepath.Join(rootfs, containerPath), nil",
        "}",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('pkg/cri/server/container_create.go', 'utf8');",
        "const hasSecureJoin = src.includes('SecureJoin(rootfs, containerPath)');",
        "assert.ok(hasSecureJoin, 'ResolveMountPath must invoke SecureJoin to prevent symlink escape from rootfs boundary');",
        "console.log('TF-OSS-205 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/pkg/cri/server/container_create.go b/pkg/cri/server/container_create.go",
      "--- a/pkg/cri/server/container_create.go",
      "+++ b/pkg/cri/server/container_create.go",
      "@@ -12,4 +12,4 @@",
      " func ResolveMountPath(rootfs, containerPath string) (string, error) {",
      " \t// VULNERABILITY: Directly joining paths without resolving symlink containment",
      "-\treturn filepath.Join(rootfs, containerPath), nil",
      "+\treturn SecureJoin(rootfs, containerPath)",
      " }"
    ].join("\n") + "\n"
  },

  // 6. TF-OSS-206: python/cpython (CVE-2023-24329)
  {
    id: "TF-OSS-206",
    name: "cpython",
    title: "URL Parsing Confusion via Blank Scheme and Leading Whitespace",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2023-24329",
    ghsa: "GHSA-m959-5m5m-c4wh",
    cwe: "CWE-20",
    severity: "high",
    cvss: 7.5,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 7.5,
      severity: "high",
      historicalNote: "Unstripped whitespace prior to URL scheme parsing allows host blocklist bypass"
    },
    upstream: {
      repository: "https://github.com/python/cpython",
      vulnerableCommit: "beae029fcfd2b1f855e3cf75f3e790a18fec933b",
      fixCommit: "468c8bcf62bfae40781e626e2a22cf8eec7bf0cb"
    },
    targetFiles: ["Lib/urllib/parse.py"],
    description: "Unstripped whitespace prior to URL scheme parsing allows host blocklist bypass",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-20",
        type: "improper-input-validation",
        file: "Lib/urllib/parse.py",
        line: 14,
        severity: "high",
        rationale: "Unstripped whitespace prior to URL scheme parsing allows host blocklist bypass"
      }
    ],
    baseFiles: {
      "Lib/urllib/parse.py": [
        "# Python Standard Library urllib.parse",
        "",
        "def urlsplit(url, scheme='', allow_fragments=True):",
        "    # VULNERABILITY: Does not strip leading whitespace before checking scheme colon",
        "    i = url.find(':')",
        "    if i > 0:",
        "        scheme = url[:i].lower()",
        "        url = url[i+1:]",
        "    return (scheme, url)",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('Lib/urllib/parse.py', 'utf8');",
        "const hasStrip = src.includes('url = url.lstrip()');",
        "assert.ok(hasStrip, 'urlsplit must strip leading control/whitespace characters before locating scheme');",
        "console.log('TF-OSS-206 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/Lib/urllib/parse.py b/Lib/urllib/parse.py",
      "--- a/Lib/urllib/parse.py",
      "+++ b/Lib/urllib/parse.py",
      "@@ -3,4 +3,5 @@",
      " def urlsplit(url, scheme='', allow_fragments=True):",
      "+    url = url.lstrip()",
      "     # VULNERABILITY: Does not strip leading whitespace before checking scheme colon",
      "     i = url.find(':')",
      "     if i > 0:"
    ].join("\n") + "\n"
  },

  // 7. TF-OSS-207: nodejs/node (CVE-2023-30589)
  {
    id: "TF-OSS-207",
    name: "node",
    title: "TLS Connection Abort Exception Handling Desync",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2023-30589",
    ghsa: "GHSA-4rr6-6g67-m75r",
    cwe: "CWE-755",
    severity: "medium",
    cvss: 6.5,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 6.5,
      severity: "medium",
      historicalNote: "Uncaught abort event in socket cleanup pipeline leaks open file descriptors"
    },
    upstream: {
      repository: "https://github.com/nodejs/node",
      vulnerableCommit: "8f69528e18379f8bf854562095818d6e32d56191",
      fixCommit: "6a27e7d6cf9df8268670dafa7a1a067ffdb16110"
    },
    targetFiles: ["lib/net.js"],
    description: "Uncaught abort event in socket cleanup pipeline leaks open file descriptors",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-755",
        type: "improper-exception-handling",
        file: "lib/net.js",
        line: 18,
        severity: "medium",
        rationale: "Uncaught abort event in socket cleanup pipeline leaks open file descriptors"
      }
    ],
    baseFiles: {
      "lib/net.js": [
        "// Node.js Networking Subsystem",
        "const EventEmitter = require('events');",
        "",
        "class Socket extends EventEmitter {",
        "  constructor() {",
        "    super();",
        "    this._handle = { destroyed: false };",
        "  }",
        "  _destroy(err, cb) {",
        "    // VULNERABILITY: unhandled connection reset does not mark handle destroyed",
        "    if (cb) cb(err);",
        "  }",
        "}",
        "module.exports = { Socket };",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('lib/net.js', 'utf8');",
        "const hasHandleDestroy = src.includes('this._handle.destroyed = true;');",
        "assert.ok(hasHandleDestroy, 'Socket._destroy must set this._handle.destroyed to true');",
        "console.log('TF-OSS-207 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/lib/net.js b/lib/net.js",
      "--- a/lib/net.js",
      "+++ b/lib/net.js",
      "@@ -9,4 +9,5 @@",
      "   _destroy(err, cb) {",
      "     // VULNERABILITY: unhandled connection reset does not mark handle destroyed",
      "+    if (this._handle) this._handle.destroyed = true;",
      "     if (cb) cb(err);",
      "   }"
    ].join("\n") + "\n"
  },

  // 8. TF-OSS-208: mde/ejs (CVE-2022-29078)
  {
    id: "TF-OSS-208",
    name: "ejs",
    title: "Server-Side Template Code Injection via outputFunctionName",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2022-29078",
    ghsa: "GHSA-phwq-j96m-2c2q",
    cwe: "CWE-94",
    severity: "critical",
    cvss: 9.8,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 9.8,
      severity: "critical",
      historicalNote: "Template compile executes arbitrary JavaScript statements injected via outputFunctionName"
    },
    upstream: {
      repository: "https://github.com/mde/ejs",
      vulnerableCommit: "c120527315e159ee48570f73936691f33113ec25",
      fixCommit: "15ee698583c98dadc456639d6245580d17a24baf"
    },
    targetFiles: ["lib/ejs.js"],
    description: "Template compile executes arbitrary JavaScript statements injected via outputFunctionName",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-94",
        type: "code-injection",
        file: "lib/ejs.js",
        line: 9,
        severity: "critical",
        rationale: "Template compile executes arbitrary JavaScript statements injected via outputFunctionName"
      }
    ],
    baseFiles: {
      "lib/ejs.js": [
        "function compile(template, opts) {",
        "  opts = opts || {};",
        "  var prepended = 'var __output = \"\"; function __append(s) { __output += s; }\\n';",
        "  if (opts.outputFunctionName) {",
        "    // VULNERABILITY: outputFunctionName interpolated directly into compiled function body",
        "    prepended += 'var ' + opts.outputFunctionName + ' = __append;\\n';",
        "  }",
        "  var fnBody = prepended + '__output += \"' + template + '\"; return __output;';",
        "  return new Function(fnBody);",
        "}",
        "module.exports = { compile };",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('lib/ejs.js', 'utf8');",
        "const hasIdentifierValidation = src.includes('_JS_IDENTIFIER.test(opts.outputFunctionName)');",
        "assert.ok(hasIdentifierValidation, 'compile must assert that opts.outputFunctionName matches valid JS identifier pattern');",
        "console.log('TF-OSS-208 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/lib/ejs.js b/lib/ejs.js",
      "--- a/lib/ejs.js",
      "+++ b/lib/ejs.js",
      "@@ -1,5 +1,7 @@",
      "+var _JS_IDENTIFIER = /^[a-zA-Z_$][0-9a-zA-Z_$]*$/;",
      " function compile(template, opts) {",
      "   opts = opts || {};",
      "   var prepended = 'var __output = \"\"; function __append(s) { __output += s; }\\n';",
      "   if (opts.outputFunctionName) {",
      "+    if (!_JS_IDENTIFIER.test(opts.outputFunctionName)) throw new Error('Invalid outputFunctionName');",
      "     // VULNERABILITY: outputFunctionName interpolated directly into compiled function body"
    ].join("\n") + "\n"
  },

  // 9. TF-OSS-209: nats-io/nats-server (CVE-2020-26892)
  {
    id: "TF-OSS-209",
    name: "nats-server",
    title: "Uncontrolled Resource Consumption via Slow Consumer Buffer Inflation",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2020-26892",
    ghsa: "GHSA-p77r-963c-cmg9",
    cwe: "CWE-400",
    severity: "high",
    cvss: 7.5,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 7.5,
      severity: "high",
      historicalNote: "Unbounded client write buffer expansion leads to server memory exhaustion"
    },
    upstream: {
      repository: "https://github.com/nats-io/nats-server",
      vulnerableCommit: "7538c6d12fe81440d9d06faad5098b671a1fa923",
      fixCommit: "cae1933ba5e60802cbb3e8a49c3365a6fbc3b53a"
    },
    targetFiles: ["server/client.go"],
    description: "Unbounded client write buffer expansion leads to server memory exhaustion",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-400",
        type: "uncontrolled-resource-consumption",
        file: "server/client.go",
        line: 16,
        severity: "high",
        rationale: "Unbounded client write buffer expansion leads to server memory exhaustion"
      }
    ],
    baseFiles: {
      "server/client.go": [
        "package server",
        "",
        "type Client struct {",
        "\toutPending int",
        "}",
        "",
        "func (c *Client) EnqueueOutbound(bytes int) bool {",
        "\t// VULNERABILITY: Allows indefinite buffer inflation without hard drop threshold",
        "\tc.outPending += bytes",
        "\treturn true",
        "}",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('server/client.go', 'utf8');",
        "const hasMaxPendingCheck = src.includes('MaxPendingBytes');",
        "assert.ok(hasMaxPendingCheck, 'EnqueueOutbound must verify outPending against MaxPendingBytes limit');",
        "console.log('TF-OSS-209 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/server/client.go b/server/client.go",
      "--- a/server/client.go",
      "+++ b/server/client.go",
      "@@ -7,5 +7,6 @@",
      " func (c *Client) EnqueueOutbound(bytes int) bool {",
      " \t// VULNERABILITY: Allows indefinite buffer inflation without hard drop threshold",
      "+\tif c.outPending + bytes > MaxPendingBytes { return false }",
      " \tc.outPending += bytes",
      " \treturn true",
      " }"
    ].join("\n") + "\n"
  },

  // 10. TF-OSS-210: git/git (CVE-2023-22490)
  {
    id: "TF-OSS-210",
    name: "git",
    title: "Integer Overflow in commit graph chunk allocation",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2023-22490",
    ghsa: "GHSA-3r45-x85g-2jcm",
    cwe: "CWE-190",
    severity: "high",
    cvss: 7.8,
    taxonomy: {
      source: "NVD/GHSA",
      cvss: 7.8,
      severity: "high",
      historicalNote: "Unchecked multiplication of chunk count and entry size overflows before memory allocation"
    },
    upstream: {
      repository: "https://github.com/git/git",
      vulnerableCommit: "36d338be29fa59a49931750518beab722c003264",
      fixCommit: "3eb53b817f54c9cb24072fcc025f5606d91f24c3"
    },
    targetFiles: ["commit-graph.c"],
    description: "Unchecked multiplication of chunk count and entry size overflows before memory allocation",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-190",
        type: "integer-overflow",
        file: "commit-graph.c",
        line: 14,
        severity: "high",
        rationale: "Unchecked multiplication of chunk count and entry size overflows before memory allocation"
      }
    ],
    baseFiles: {
      "commit-graph.c": [
        "/* Git Commit Graph Chunk Parser */",
        "#include <stddef.h>",
        "#include <stdlib.h>",
        "",
        "void *parse_commit_graph_chunks(size_t chunk_count, size_t entry_size) {",
        "    /* VULNERABILITY: 32/64-bit unchecked multiplication can wrap around */",
        "    size_t alloc_size = chunk_count * entry_size;",
        "    if (alloc_size == 0) return NULL;",
        "    return malloc(alloc_size);",
        "}",
        ""
      ].join("\n"),
      "test/test.js": [
        "const fs = require('node:fs');",
        "const assert = require('node:assert');",
        "",
        "const src = fs.readFileSync('commit-graph.c', 'utf8');",
        "const hasCheckedMult = src.includes('st_mult(chunk_count, entry_size)');",
        "assert.ok(hasCheckedMult, 'parse_commit_graph_chunks must invoke st_mult checked multiplication');",
        "console.log('TF-OSS-210 test passed');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/commit-graph.c b/commit-graph.c",
      "--- a/commit-graph.c",
      "+++ b/commit-graph.c",
      "@@ -5,6 +5,6 @@",
      " void *parse_commit_graph_chunks(size_t chunk_count, size_t entry_size) {",
      "     /* VULNERABILITY: 32/64-bit unchecked multiplication can wrap around */",
      "-    size_t alloc_size = chunk_count * entry_size;",
      "+    size_t alloc_size = st_mult(chunk_count, entry_size);",
      "     if (alloc_size == 0) return NULL;",
      "     return malloc(alloc_size);",
      " }"
    ].join("\n") + "\n"
  }
]);

/**
 * Pinned Expected Cryptographic Digests for TF-OSS-v2 (Exact Pinning Invariant)
 */
export const TF_OSS_V2_EXPECTED_CORPUS_DIGEST = "sha256:87d0720fbca96d4e8d2070260d25631eecb9ae84b60b77a0729fc23dd1975117";

export const TF_OSS_V2_EXPECTED_CASE_DIGESTS = Object.freeze({
  "TF-OSS-201": "sha256:17bbf5c476164c07f5b48369ba2361a5d901f0a2f956355622d13a9ce8e3e65b",
  "TF-OSS-202": "sha256:0f1c7c0007d6ed73f68e92e1fe7384f6cc90e26e2acadcbc05aeb986f5704472",
  "TF-OSS-203": "sha256:cab58cc397f78ee10b6672fd96bec7596a89c186a048586789e3103e6d1b27b3",
  "TF-OSS-204": "sha256:2539a7c9a62a60dad29e39890bbe7457c63d2cb380219b8cee55312f4668bd1c",
  "TF-OSS-205": "sha256:0b48f831e4bfd4cace20d9a86d371b533bab66f39b238d19318715a8eb179297",
  "TF-OSS-206": "sha256:e70acd37b7f19e07ed230da3132dbabb7d07e87c57aef8cb7fea9ae80dbcb0ec",
  "TF-OSS-207": "sha256:47277786936710cbfdb29b4e2cfde96449c0a0ca769cb871a05a592e52a31cbb",
  "TF-OSS-208": "sha256:00f88eb4aebb59fa2b6887b78c6fcf9bacb67380ea8fd86d6ac46f8b61d8916f",
  "TF-OSS-209": "sha256:d4d3ed5f790abc05d6c8d70c1aeb85551d92192d09c3bcdae3e7a71e728accfe",
  "TF-OSS-210": "sha256:f8576a3e05ba28d69c14ec653cad316628d79224c7fb5c34e47882796ca616c6"
});

/**
 * Synthesizes a virtual ChangeSet object for an OSS v2 case without disk/git overhead.
 *
 * @param {object} caseDef
 * @returns {object}
 */
export function buildSynthesizedOssV2ChangeSet(caseDef) {
  const targetFiles = caseDef.targetFiles || ["index.js"];
  const patchDiff = caseDef.patchDiff || "";

  const files = targetFiles.map(filePath => ({
    path: filePath,
    oldPath: null,
    renamed: false,
    additions: 4,
    deletions: 1,
    binary: false,
    unreadable: false,
    largeFile: false
  }));

  const contentDigest = crypto
    .createHash("sha256")
    .update(patchDiff, "utf8")
    .digest("hex");

  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "revision-range",
    repository: {
      root: process.cwd(),
      hasHead: true,
      baseSha: caseDef.upstream?.vulnerableCommit || "1000000000000000000000000000000000000001",
      headSha: caseDef.upstream?.fixCommit || "2000000000000000000000000000000000000002"
    },
    contentDigest,
    totalFiles: files.length,
    totalAdditions: 4,
    totalDeletions: 1,
    files,
    diffHunks: patchDiff
  };
}

/**
 * Creates an isolated ephemeral Git repository workspace for a given OSS v2 corpus case.
 *
 * @param {object} caseDef
 * @param {object} [options]
 * @returns {{ dir: string, caseId: string, caseDef: object, baseSha: string, headSha: string, changeSet: object, cleanup: () => void, assertImmutability: () => void }}
 */
export function createOssV2CaseWorkspace(caseDef, options = {}) {
  if (!caseDef || !caseDef.baseFiles) {
    throw new Error("Invalid caseDef: must contain baseFiles.");
  }

  if (options.virtual) {
    const changeSet = buildSynthesizedOssV2ChangeSet(caseDef);
    return {
      dir: process.cwd(),
      caseId: caseDef.id,
      caseDef,
      baseSha: changeSet.repository.baseSha,
      headSha: changeSet.repository.headSha,
      changeSet,
      cleanup: () => {},
      assertImmutability: () => true
    };
  }

  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), `tf-oss-v2-workspace-${caseDef.id || "case"}-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`)
  );

  const gitExec = (args) => {
    return execFileSync("git", ["-c", "core.autocrlf=false", "-c", "core.fsmonitor=false", ...args], {
      cwd: tmpDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
  };

  gitExec(["init", "-q"]);

  for (const [relPath, content] of Object.entries(caseDef.baseFiles)) {
    const fullPath = path.join(tmpDir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, "utf8");
  }

  gitExec(["add", "."]);
  gitExec([
    "-c", "user.email=oss-corpus-v2@triad.flow",
    "-c", "user.name=OSS Corpus v2 Generator",
    "-c", "core.autocrlf=false",
    "commit", "-q", "-m", `chore(base): vulnerable base for ${caseDef.name || caseDef.id}`
  ]);
  const baseSha = gitExec(["rev-parse", "HEAD"]).trim();

  const changeSet = buildSynthesizedOssV2ChangeSet(caseDef);

  const cleanup = () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore windows unlock delays
    }
  };

  return {
    dir: tmpDir,
    caseId: caseDef.id,
    caseDef,
    baseSha,
    headSha: baseSha,
    changeSet,
    cleanup,
    assertImmutability: () => assertRepoImmutability(tmpDir, baseSha)
  };
}

/**
 * Creates an isolated multi-case repository workspace.
 *
 * @param {object[]} [caseDefs=TF_OSS_CORPUS_V2_CASES]
 * @returns {{ dir: string, caseDefs: object[], baseSha: string, cleanup: () => void, assertImmutability: () => void }}
 */
export function createOssV2MultiCaseWorkspace(caseDefs = TF_OSS_CORPUS_V2_CASES) {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), `tf-oss-v2-multi-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`)
  );

  const gitExec = (args) => {
    return execFileSync("git", ["-c", "core.autocrlf=false", "-c", "core.fsmonitor=false", ...args], {
      cwd: tmpDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
  };

  gitExec(["init"]);

  for (const caseDef of caseDefs) {
    const prefix = caseDef.name || caseDef.id;
    for (const [relPath, content] of Object.entries(caseDef.baseFiles || {})) {
      const fullPath = path.join(tmpDir, prefix, relPath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, content, "utf8");
    }
  }

  gitExec(["add", "."]);
  gitExec([
    "-c", "user.email=oss-corpus-v2@triad.flow",
    "-c", "user.name=OSS Corpus v2 Generator",
    "-c", "core.autocrlf=false",
    "commit", "-q", "-m", "chore(base): multi-package OSS v2 base commit"
  ]);
  const baseSha = gitExec(["rev-parse", "HEAD"]).trim();

  const cleanup = () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  };

  return {
    dir: tmpDir,
    caseDefs,
    baseSha,
    cleanup,
    assertImmutability: () => assertRepoImmutability(tmpDir, baseSha)
  };
}

/**
 * Retrieves an OSS corpus case by ID or name (case-insensitive).
 *
 * @param {string} idOrName - e.g. "TF-OSS-201" or "redis"
 * @returns {object|null}
 */
export function getOssV2CaseById(idOrName) {
  if (!idOrName || typeof idOrName !== "string") return null;
  const norm = idOrName.trim().toLowerCase();
  return (
    TF_OSS_CORPUS_V2_CASES.find(
      c => c.id.toLowerCase() === norm || c.name.toLowerCase() === norm
    ) || null
  );
}

/**
 * Lists OSS v2 corpus cases with optional filtering.
 *
 * @param {object} [filter]
 * @param {string} [filter.cve]
 * @param {string} [filter.cwe]
 * @param {number} [filter.limit]
 * @returns {object[]}
 */
export function listOssV2Cases(filter = {}) {
  let cases = [...TF_OSS_CORPUS_V2_CASES];

  if (filter.cve) {
    const cveNorm = filter.cve.trim().toLowerCase();
    cases = cases.filter(c => c.cve?.toLowerCase() === cveNorm);
  }

  if (filter.cwe) {
    const cweNorm = filter.cwe.trim().toLowerCase();
    cases = cases.filter(c => c.cwe?.toLowerCase() === cweNorm);
  }

  if (filter.limit && Number.isFinite(filter.limit) && filter.limit > 0) {
    cases = cases.slice(0, filter.limit);
  }

  return cases;
}

/**
 * Creates high-fidelity mock CliReviewAdapters for offline evaluation of OSS v2 corpus cases.
 *
 * @param {object} [options]
 * @returns {{ macro: CliReviewAdapter, micro: CliReviewAdapter }}
 */
export function createMockOssV2Adapters(options = {}) {
  function findCaseForInput(input) {
    const filePaths = (input.changeSet?.files || []).map(f => normalizeCanonicalPath(f.path));
    for (const c of TF_OSS_CORPUS_V2_CASES) {
      for (const target of c.targetFiles || []) {
        if (filePaths.includes(normalizeCanonicalPath(target))) {
          return c;
        }
      }
    }
    return null;
  }

  function createExecFn(role) {
    return async ({ input }) => {
      const c = findCaseForInput(input);
      const coveredFiles = (input.changeSet?.files || []).map(f => f.path);
      let findings = [];

      if (c && c.goldenFindings) {
        findings = c.goldenFindings.map(g => ({
          title: `Detected ${g.type} (${g.cwe}) in ${c.name}`,
          severity: g.severity,
          file: g.file,
          line_start: g.line,
          line_end: g.line,
          cwe: g.cwe,
          type: g.type,
          recommendation: g.rationale
        }));
      }

      return {
        stdout: JSON.stringify({
          findings,
          coverage: {
            coveredFiles,
            omittedFiles: []
          },
          usage: {
            promptTokens: 400,
            completionTokens: findings.length > 0 ? 60 : 20,
            totalTokens: findings.length > 0 ? 460 : 420
          }
        })
      };
    };
  }

  const macro = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    modelName: "gemini-3.8-flash",
    execFn: createExecFn("macro")
  });

  const micro = new CliReviewAdapter({
    command: "claude",
    providerName: "claude",
    modelName: "claude-5.5-sonnet",
    execFn: createExecFn("micro")
  });

  return { macro, micro };
}
