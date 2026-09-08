/**
 * Hardened Git Numstat Parser
 * Canonical Parser supporting standard and NUL-delimited Git streams with space, rename, and binary preservation.
 */

export function resolveRenamePath(rawPath = "") {
  if (!rawPath || typeof rawPath !== "string") return { path: "", oldPath: null, renamed: false };

  // Handle brace format: src/{old => new}/file.js or {old => new}.js
  const braceMatch = rawPath.match(/^(.*?)\{(.*?) => (.*?)\}(.*?)$/);
  if (braceMatch) {
    const [, prefix, oldPart, newPart, suffix] = braceMatch;
    const oldPath = `${prefix}${oldPart}${suffix}`.replace(/\/{2,}/g, "/");
    const newPath = `${prefix}${newPart}${suffix}`.replace(/\/{2,}/g, "/");
    return { path: newPath, oldPath, renamed: true };
  }

  // Handle plain arrow: old.js => new.js
  const arrowMatch = rawPath.match(/^(.*?) => (.*?)$/);
  if (arrowMatch) {
    const [, oldPath, newPath] = arrowMatch;
    return { path: newPath, oldPath, renamed: true };
  }

  // Unquoted standard path
  return { path: rawPath, oldPath: null, renamed: false };
}

function decodeGitCStyleString(str = "") {
  if (!str.startsWith('"') || !str.endsWith('"')) {
    return str;
  }
  const inner = str.slice(1, -1);
  return inner.replace(/\\([0-7]{1,3}|[\\"/trn])/g, (match, p1) => {
    if (p1 === '"') return '"';
    if (p1 === "\\") return "\\";
    if (p1 === "/") return "/";
    if (p1 === "t") return "\t";
    if (p1 === "r") return "\r";
    if (p1 === "n") return "\n";
    if (/^[0-7]{1,3}$/.test(p1)) {
      return String.fromCharCode(parseInt(p1, 8));
    }
    return match;
  });
}

/**
 * Authoritative NUL-delimited parser for `git diff --numstat -z`.
 * Preserves raw POSIX backslashes and UTF-8 characters.
 */
export function parseNumstatZ(rawText = "") {
  if (!rawText || typeof rawText !== "string") return [];

  const tokens = rawText.split("\0");
  const results = [];
  let i = 0;

  while (i < tokens.length) {
    const header = tokens[i++];
    if (!header) continue;

    const parts = header.split("\t");
    if (parts.length < 2) continue;

    const isBinary = parts[0] === "-" && parts[1] === "-";
    const additions = isBinary ? 0 : parseInt(parts[0], 10) || 0;
    const deletions = isBinary ? 0 : parseInt(parts[1], 10) || 0;

    if (parts.length >= 3 && parts[2] !== "") {
      // Standard file record: additions\tdeletions\tfilePath
      results.push({
        path: parts.slice(2).join("\t"),
        oldPath: null,
        renamed: false,
        additions,
        deletions,
        binary: isBinary
      });
    } else {
      // Git -z rename format: additions\tdeletions\t\0oldPath\0newPath\0
      const oldPath = tokens[i++];
      const newPath = tokens[i++];
      if (newPath !== undefined) {
        results.push({
          path: newPath,
          oldPath: oldPath || null,
          renamed: true,
          additions,
          deletions,
          binary: isBinary
        });
      }
    }
  }

  return results;
}

/**
 * Standard line-delimited numstat parser.
 */
export function parseNumstat(diffText = "") {
  if (!diffText || typeof diffText !== "string") return [];

  const lines = diffText.trim().split("\n");
  const results = [];

  for (const line of lines) {
    if (!line.trim()) continue;

    const parts = line.split("\t");
    if (parts.length < 3) continue;

    const addStr = parts[0];
    const delStr = parts[1];
    const rawPathPart = parts.slice(2).join("\t");

    const isBinary = addStr === "-" && delStr === "-";
    const additions = isBinary ? 0 : parseInt(addStr, 10) || 0;
    const deletions = isBinary ? 0 : parseInt(delStr, 10) || 0;

    const decodedPath = decodeGitCStyleString(rawPathPart);
    const renameInfo = resolveRenamePath(decodedPath);

    results.push({
      path: renameInfo.path,
      oldPath: renameInfo.oldPath,
      renamed: renameInfo.renamed,
      additions,
      deletions,
      binary: isBinary
    });
  }

  return results;
}
