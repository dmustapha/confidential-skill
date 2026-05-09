#!/usr/bin/env node
/**
 * ap-lint — FHEVM Anti-Pattern Linter
 * Scans Solidity files for AP-001 through AP-020 violations from SKILL.md
 *
 * Usage:
 *   node tools/ap-lint.js [files...] [--dir <path>]
 *   node tools/ap-lint.js contracts/MyToken.sol
 *   node tools/ap-lint.js --dir contracts/
 */

const fs = require("fs");
const path = require("path");

const RULES = [
  {
    id: "AP-001",
    severity: "CRITICAL",
    title: "Wrong package import",
    test: (src) => /['"]fhevm-solidity/.test(src),
    message: "Imports from `fhevm-solidity` — package archived June 2025. Use `@fhevm/solidity`.",
    fix: "Replace: import \"fhevm-solidity/...\" → import \"@fhevm/solidity/lib/FHE.sol\"",
  },
  {
    id: "AP-002",
    severity: "CRITICAL",
    title: "Missing ZamaEthereumConfig base contract",
    test: (src) =>
      /import.*@fhevm\/solidity/.test(src) &&
      !/ZamaEthereumConfig|ZamaDevnetConfig|ZamaLocalConfig/.test(src),
    message: "No Zama config base contract detected. Gateway addresses will be zero.",
    fix: 'Add: import "@fhevm/solidity/config/ZamaConfig.sol"; and inherit ZamaEthereumConfig',
  },
  {
    id: "AP-003",
    severity: "CRITICAL",
    title: "Missing FHE.allowThis() after handle storage",
    test: (src) => {
      // Detect state writes via FHE operations (e.g. _var[x] = FHE.add(...))
      // without FHE.allowThis() in the next 5 lines.
      const lines = src.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Match: _stateVar[...] = FHE.<anything>(...)
        if (/^\s*_\w+(\[.*?\])?\s*=\s*FHE\./.test(line) && !/FHE\.allowThis|FHE\.allow\(/.test(line)) {
          const window = lines.slice(i, i + 6).join("\n");
          if (!/FHE\.allowThis|FHE\.allow\(/.test(window)) return true;
        }
      }
      return false;
    },
    message: "Encrypted handle stored without FHE.allowThis() in vicinity — handle may become inaccessible.",
    fix: "Add FHE.allowThis(handle) immediately after storing an encrypted value.",
  },
  {
    id: "AP-004",
    severity: "CRITICAL",
    title: "euint256 arithmetic",
    test: (src) => /euint256/.test(src) && /FHE\.(add|sub|mul|div|rem|shl|shr|lt|le|gt|ge|min|max)\s*\(/.test(src),
    message: "euint256 does not support arithmetic or comparison ops — only eq/ne/and/or/xor/select.",
    fix: "Use euint128 or lower for arithmetic. Check all FHE ops on euint256.",
  },
  {
    id: "AP-005",
    severity: "CRITICAL",
    title: "Synchronous decrypt (removed)",
    test: (src) => /TFHE\.decrypt|\.decrypt\s*\(/.test(src),
    message: "Synchronous decrypt was removed in v0.5. Use FHE.makePubliclyDecryptable + relayer SDK.",
    fix: "Replace TFHE.decrypt() with FHE.makePubliclyDecryptable(handle) + off-chain relayer read.",
  },
  {
    id: "AP-006",
    severity: "CRITICAL",
    title: "FHE.div/rem with encrypted divisor",
    test: (src) => /FHE\.(div|rem)\s*\(\s*\w+\s*,\s*(euint|e[0-9])/.test(src),
    message: "FHE.div/rem second argument must be a plaintext uint, not an encrypted type.",
    fix: "Use FHE.div(encryptedNumerator, plaintextDivisor). Decrypt divisor first if needed.",
  },
  {
    id: "AP-007",
    severity: "CRITICAL",
    title: "Raw uint input without ZKPoK",
    test: (src) => /function\s+\w+[^)]*uint\d*\s+\w+[^)]*\)\s*(external|public)/.test(src) &&
      !/externalE(uint|bool|address|int|bytes)/.test(src) &&
      /import.*@fhevm\/solidity/.test(src),
    message: "Function accepts raw uint without ZKPoK validation — replay/frontrun risk.",
    fix: "Change parameter to externalEuint64 + bytes calldata inputProof, then call FHE.fromExternal().",
  },
  {
    id: "AP-009",
    severity: "IMPORTANT",
    title: "eaddress arithmetic",
    test: (src) => /FHE\.(add|sub|mul|div)\s*\(.*eaddress/.test(src),
    message: "eaddress only supports equality checks (eq/ne/select). No arithmetic.",
    fix: "Use eaddress only for FHE.eq(addr1, addr2) comparisons.",
  },
  {
    id: "AP-012",
    severity: "IMPORTANT",
    title: "Direct comparison of encrypted values",
    test: (src) => /(euint|ebool|eaddress)\w*\s*==\s*(euint|ebool|eaddress)/.test(src),
    message: "Cannot compare encrypted handles with ==. Use FHE.eq() which returns ebool.",
    fix: "Replace: a == b → FHE.eq(a, b) returns ebool.",
  },
  {
    id: "AP-013",
    severity: "IMPORTANT",
    title: "Hardcoded network address",
    test: (src) => /address\s*\(\s*0x[0-9a-fA-F]{40}\s*\)/.test(src) &&
      !/test|Test|mock|Mock/.test(src),
    message: "Hardcoded address detected in non-test contract — breaks on network change.",
    fix: "Use ZamaEthereumConfig base contract for gateway/KMS addresses.",
  },
  {
    id: "AP-015",
    severity: "IMPORTANT",
    title: "ACL access without FHE.isAllowed() check",
    test: (src) => /FHE\.makePubliclyDecryptable/.test(src) &&
      !/FHE\.isAllowed\(/.test(src),
    message: "Granting ACL without checking FHE.isAllowed() — may allow unauthorized re-encryption.",
    fix: "Guard with: require(FHE.isAllowed(handle, msg.sender), \"Not allowed\");",
  },
  {
    id: "AP-016",
    severity: "IMPORTANT",
    title: "Missing reentrancy guard on decrypt callback",
    test: (src) => /callback|Callback/.test(src) &&
      /decrypt|Decrypt/.test(src) &&
      !/nonReentrant|ReentrancyGuard/.test(src),
    message: "Decrypt callback without reentrancy guard — vulnerable to reentrant calls.",
    fix: "Add: import OpenZeppelin ReentrancyGuard and mark callback nonReentrant.",
  },
  {
    id: "AP-019",
    severity: "IMPORTANT",
    title: "Missing access control on admin functions",
    test: (src) => /function\s+(mint|pause|unpause|setOwner|transfer[Oo]wnership)\s*\(/.test(src) &&
      !/onlyOwner|onlyRole|require\s*\(\s*msg\.sender\s*==/.test(src),
    message: "Admin function without access control — anyone can call it.",
    fix: "Add onlyOwner modifier from OpenZeppelin Ownable, or use AccessControl.",
  },
  {
    id: "AP-020",
    severity: "IMPORTANT",
    title: "Storing plaintext alongside encrypted data",
    test: (src) => {
      const lines = src.split("\n");
      for (const line of lines) {
        if (/\buint\d*\s+(amount|balance|value|price|quantity)\b/.test(line) &&
            !/\/\/|mapping|constant|immutable|event\s|function\s/.test(line)) return true;
      }
      return false;
    },
    message: "Plaintext sensitive variable detected — consider whether this should be encrypted.",
    fix: "Use euint64 for sensitive financial values. Store encrypted handles, not plaintexts.",
  },
];

function lint(filePath) {
  const src = fs.readFileSync(filePath, "utf8");
  const violations = [];
  for (const rule of RULES) {
    try {
      if (rule.test(src)) {
        violations.push(rule);
      }
    } catch (_) {
      // rule test error — skip
    }
  }
  return violations;
}

function findSolFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name !== "node_modules") {
      results.push(...findSolFiles(full));
    } else if (entry.isFile() && entry.name.endsWith(".sol")) {
      results.push(full);
    }
  }
  return results;
}

// Parse args
const args = process.argv.slice(2);
let files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--dir" && args[i + 1]) {
    files.push(...findSolFiles(args[++i]));
  } else if (fs.existsSync(args[i])) {
    const stat = fs.statSync(args[i]);
    if (stat.isDirectory()) files.push(...findSolFiles(args[i]));
    else files.push(args[i]);
  }
}

if (files.length === 0) {
  // Default: scan contracts/ in cwd
  const defaultDir = path.join(process.cwd(), "contracts");
  if (fs.existsSync(defaultDir)) {
    files = findSolFiles(defaultDir);
  } else {
    console.error("Usage: node tools/ap-lint.js [files...] [--dir <path>]");
    console.error("No contracts/ directory found in current directory.");
    process.exit(1);
  }
}

let totalViolations = 0;
let filesWithViolations = 0;

for (const file of files) {
  const violations = lint(file);
  if (violations.length > 0) {
    filesWithViolations++;
    totalViolations += violations.length;
    console.log(`\n${file}`);
    for (const v of violations) {
      const prefix = v.severity === "CRITICAL" ? "✗" : "⚠";
      console.log(`  ${prefix} [${v.id}] ${v.severity}: ${v.title}`);
      console.log(`    ${v.message}`);
      console.log(`    Fix: ${v.fix}`);
    }
  }
}

if (totalViolations === 0) {
  console.log(`✓ ${files.length} file(s) scanned — no AP violations found`);
  process.exit(0);
} else {
  const criticals = RULES.filter(r => r.severity === "CRITICAL").map(r => r.id);
  const hasCritical = files.some(f => {
    const src = fs.readFileSync(f, "utf8");
    return criticals.some(id => {
      const rule = RULES.find(r => r.id === id);
      try { return rule.test(src); } catch(_) { return false; }
    });
  });
  console.log(`\n${totalViolations} violation(s) in ${filesWithViolations}/${files.length} file(s)`);
  process.exit(hasCritical ? 2 : 1);
}
