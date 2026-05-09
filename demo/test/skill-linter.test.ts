/**
 * Tier 4B — AP Linter Functional Tests
 *
 * Run with: npm test
 *
 * Verifies AP-001 through AP-020 documented in SKILL.md (14 rules implemented
 * statically; AP-008, 010, 011, 014, 017, 018 require manual review) are correctly
 * detected by tools/ap-lint.js and correctly NOT detected (false-positive check).
 *
 * Architecture:
 *   - Each "should detect" test writes a minimal violating Solidity snippet to a
 *     temp file and asserts the linter exits with code 1 (IMPORTANT) or 2 (CRITICAL).
 *   - The "clean contracts" test asserts the linter exits 0 on the demo contracts.
 *   - Temp files are cleaned up after each test.
 */

import { expect } from "chai";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const LINTER = path.resolve(__dirname, "../../confidential-skill/tools/ap-lint.js");
const DEMO_CONTRACTS = path.resolve(__dirname, "../contracts");
const TMP_DIR = path.resolve(__dirname, "../tmp-lint-fixtures");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function runLinter(filePath: string): { exitCode: number; stdout: string } {
  try {
    const stdout = execSync(`node "${LINTER}" "${filePath}"`, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { exitCode: 0, stdout };
  } catch (err: any) {
    return { exitCode: err.status ?? 1, stdout: err.stdout ?? "" };
  }
}

function writeTmp(name: string, content: string): string {
  fs.mkdirSync(TMP_DIR, { recursive: true });
  const p = path.join(TMP_DIR, name);
  fs.writeFileSync(p, content, "utf8");
  return p;
}

function cleanup() {
  if (fs.existsSync(TMP_DIR)) {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Minimal FHEVM preamble (used in most snippets)
// ---------------------------------------------------------------------------

const PREAMBLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "@fhevm/solidity/lib/FHE.sol";
import "@fhevm/solidity/config/ZamaConfig.sol";
`;

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("AP Linter — Functional Tests (Tier 4B)", function () {
  after(cleanup);

  // -------------------------------------------------------------------------
  // False-positive gate: demo contracts must be clean
  // -------------------------------------------------------------------------
  describe("False-positive gate: demo contracts have 0 violations", function () {
    it("ConfidentialERC20.sol passes with exit 0", function () {
      const f = path.join(DEMO_CONTRACTS, "ConfidentialERC20.sol");
      const { exitCode } = runLinter(f);
      expect(exitCode).to.equal(0, "ConfidentialERC20.sol should have 0 AP violations");
    });

    it("SealedBidAuction.sol passes with exit 0", function () {
      const f = path.join(DEMO_CONTRACTS, "SealedBidAuction.sol");
      const { exitCode } = runLinter(f);
      expect(exitCode).to.equal(0, "SealedBidAuction.sol should have 0 AP violations");
    });

    it("ConfidentialVote.sol passes with exit 0", function () {
      const f = path.join(DEMO_CONTRACTS, "ConfidentialVote.sol");
      const { exitCode } = runLinter(f);
      expect(exitCode).to.equal(0, "ConfidentialVote.sol should have 0 AP violations");
    });
  });

  // -------------------------------------------------------------------------
  // CRITICAL violations (exit code 2)
  // -------------------------------------------------------------------------
  describe("CRITICAL violations (exit code 2)", function () {
    it("AP-001: detects fhevm-solidity import (archived package)", function () {
      const f = writeTmp("bad-ap001.sol", `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "fhevm-solidity/lib/TFHE.sol";
import "@fhevm/solidity/config/ZamaConfig.sol";
contract Bad001 is ZamaEthereumConfig {}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(2, "AP-001 must trigger CRITICAL exit");
      expect(stdout).to.include("AP-001");
    });

    it("AP-002: detects missing ZamaEthereumConfig base contract", function () {
      const f = writeTmp("bad-ap002.sol", `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "@fhevm/solidity/lib/FHE.sol";
contract Bad002 {
    euint64 private _value;
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(2, "AP-002 must trigger CRITICAL exit");
      expect(stdout).to.include("AP-002");
    });

    it("AP-003: detects missing FHE.allowThis after handle storage", function () {
      const f = writeTmp("bad-ap003.sol", `${PREAMBLE}
contract Bad003 is ZamaEthereumConfig {
    mapping(address => euint64) private _b;
    function store(externalEuint64 enc, bytes calldata proof) external {
        _b[msg.sender] = FHE.fromExternal(enc, proof);
        // missing permission grant — AP-003 violation
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(2, "AP-003 must trigger CRITICAL exit");
      expect(stdout).to.include("AP-003");
    });

    it("AP-004: detects euint256 arithmetic (FHE.add on euint256)", function () {
      const f = writeTmp("bad-ap004.sol", `${PREAMBLE}
contract Bad004 is ZamaEthereumConfig {
    euint256 private _reward;
    function accumulate(euint256 more) external {
        _reward = FHE.add(_reward, more);
        FHE.allowThis(_reward);
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(2, "AP-004 must trigger CRITICAL exit");
      expect(stdout).to.include("AP-004");
    });

    it("AP-005: detects synchronous decrypt (TFHE.decrypt)", function () {
      const f = writeTmp("bad-ap005.sol", `${PREAMBLE}
contract Bad005 is ZamaEthereumConfig {
    euint64 private _bal;
    function peek() external view returns (uint64) {
        return TFHE.decrypt(_bal);
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(2, "AP-005 must trigger CRITICAL exit");
      expect(stdout).to.include("AP-005");
    });

    it("AP-006: detects FHE.div with encrypted divisor", function () {
      const f = writeTmp("bad-ap006.sol", `${PREAMBLE}
contract Bad006 is ZamaEthereumConfig {
    euint64 private _a;
    function divByEnc(externalEuint64 enc, bytes calldata proof) external {
        euint64 e2 = FHE.fromExternal(enc, proof);
        euint64 result = FHE.div(_a, e2);
        FHE.allowThis(result);
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(2, "AP-006 must trigger CRITICAL exit");
      expect(stdout).to.include("AP-006");
    });

    it("AP-007: detects raw uint input without ZKPoK in FHEVM contract", function () {
      const f = writeTmp("bad-ap007.sol", `${PREAMBLE}
contract Bad007 is ZamaEthereumConfig {
    mapping(address => euint64) private _b;
    function deposit(uint64 rawAmount) external {
        _b[msg.sender] = FHE.add(_b[msg.sender], FHE.asEuint64(rawAmount));
        FHE.allowThis(_b[msg.sender]);
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(2, "AP-007 must trigger CRITICAL exit");
      expect(stdout).to.include("AP-007");
    });
  });

  // -------------------------------------------------------------------------
  // IMPORTANT violations (exit code 1)
  // -------------------------------------------------------------------------
  describe("IMPORTANT violations (exit code 1)", function () {
    it("AP-009: detects eaddress arithmetic (FHE.add on eaddress)", function () {
      const f = writeTmp("bad-ap009.sol", `${PREAMBLE}
contract Bad009 is ZamaEthereumConfig {
    eaddress private eaddress1;
    eaddress private eaddress2;
    function combine() external {
        eaddress r = FHE.add(eaddress1, eaddress2);
        FHE.allowThis(r);
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(1, "AP-009 must trigger IMPORTANT exit");
      expect(stdout).to.include("AP-009");
    });

    it("AP-012: detects direct == comparison of encrypted values", function () {
      const f = writeTmp("bad-ap012.sol", `${PREAMBLE}
contract Bad012 is ZamaEthereumConfig {
    euint64 private _a;
    euint64 private _b;
    function eq() external view returns (bool) {
        euint64 euintA = _a;
        euint64 euintB = _b;
        return euintA == euintB;
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(1, "AP-012 must trigger IMPORTANT exit");
      expect(stdout).to.include("AP-012");
    });

    it("AP-013: detects hardcoded network address in non-test contract", function () {
      const f = writeTmp("bad-ap013.sol", `${PREAMBLE}
contract Bad013 is ZamaEthereumConfig {
    address constant GATEWAY = address(0xe3a9105a3a932253a70f126eb1e3b589c643dd24);
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(1, "AP-013 must trigger IMPORTANT exit");
      expect(stdout).to.include("AP-013");
    });

    it("AP-015: detects makePubliclyDecryptable without FHE.isAllowed guard", function () {
      const f = writeTmp("bad-ap015.sol", `${PREAMBLE}
contract Bad015 is ZamaEthereumConfig {
    mapping(address => euint64) private _b;
    function revealBalance() external {
        // Missing FHE.isAllowed check — AP-015 violation
        FHE.makePubliclyDecryptable(_b[msg.sender]);
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(1, "AP-015 must trigger IMPORTANT exit");
      expect(stdout).to.include("AP-015");
    });

    it("AP-016: detects decrypt callback without reentrancy guard", function () {
      const f = writeTmp("bad-ap016.sol", `${PREAMBLE}
contract Bad016 is ZamaEthereumConfig {
    mapping(address => euint64) private _b;
    function deposit(externalEuint64 enc, bytes calldata proof) external {
        _b[msg.sender] = FHE.fromExternal(enc, proof);
        FHE.allowThis(_b[msg.sender]);
        FHE.allow(_b[msg.sender], msg.sender);
    }
    function onDecryptCallback(uint64 decryptedValue) external {
        // no reentrancy guard here — AP-016
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(1, "AP-016 must trigger IMPORTANT exit");
      expect(stdout).to.include("AP-016");
    });

    it("AP-019: detects mint function without access control", function () {
      const f = writeTmp("bad-ap019.sol", `${PREAMBLE}
contract Bad019 is ZamaEthereumConfig {
    mapping(address => euint64) private _b;
    function deposit(externalEuint64 enc, bytes calldata proof) external {
        _b[msg.sender] = FHE.fromExternal(enc, proof);
        FHE.allowThis(_b[msg.sender]);
        FHE.allow(_b[msg.sender], msg.sender);
    }
    function mint(address to, externalEuint64 enc, bytes calldata proof) external {
        // no access control here — AP-019 violation
        euint64 amount = FHE.fromExternal(enc, proof);
        _b[to] = FHE.add(_b[to], amount);
        FHE.allowThis(_b[to]);
    }
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(1, "AP-019 must trigger IMPORTANT exit");
      expect(stdout).to.include("AP-019");
    });

    it("AP-020: detects plaintext state variable alongside encrypted data", function () {
      const f = writeTmp("bad-ap020.sol", `${PREAMBLE}
import "@openzeppelin/contracts/access/Ownable.sol";
contract Bad020 is ZamaEthereumConfig, Ownable {
    mapping(address => euint64) private _encBalances;
    uint64 balance;
    constructor() Ownable(msg.sender) {}
}
`);
      const { exitCode, stdout } = runLinter(f);
      expect(exitCode).to.equal(1, "AP-020 must trigger IMPORTANT exit");
      expect(stdout).to.include("AP-020");
    });
  });

  // -------------------------------------------------------------------------
  // False-negative gate: clean contracts must NOT trigger these rules
  // -------------------------------------------------------------------------
  describe("False-negative gate: AP-020 does NOT flag encrypted or param uses", function () {
    it("euint64 local variable named 'amount' does NOT trigger AP-020", function () {
      const f = writeTmp("clean-euint-amount.sol", `${PREAMBLE}
import "@openzeppelin/contracts/access/Ownable.sol";
contract Clean is ZamaEthereumConfig, Ownable {
    mapping(address => euint64) private _b;
    constructor() Ownable(msg.sender) {}
    function deposit(externalEuint64 encAmt, bytes calldata proof) external {
        euint64 amount = FHE.fromExternal(encAmt, proof);
        _b[msg.sender] = FHE.add(_b[msg.sender], amount);
        FHE.allowThis(_b[msg.sender]);
        FHE.allow(_b[msg.sender], msg.sender);
    }
}
`);
      const { exitCode } = runLinter(f);
      expect(exitCode).to.equal(0, "euint64 local var should not trigger AP-020");
    });

    it("function parameter 'uint64 amount' does NOT trigger AP-020", function () {
      const f = writeTmp("clean-param-amount.sol", `${PREAMBLE}
import "@openzeppelin/contracts/access/Ownable.sol";
contract Clean2 is ZamaEthereumConfig, Ownable {
    mapping(address => euint64) private _b;
    constructor() Ownable(msg.sender) {}
    function deposit(externalEuint64 enc, bytes calldata proof) external {
        _b[msg.sender] = FHE.fromExternal(enc, proof);
        FHE.allowThis(_b[msg.sender]);
        FHE.allow(_b[msg.sender], msg.sender);
    }
    function mint(address to, uint64 amount) external onlyOwner {
        _b[to] = FHE.add(_b[to], FHE.asEuint64(amount));
        FHE.allowThis(_b[to]);
        FHE.allow(_b[to], to);
    }
}
`);
      const { exitCode } = runLinter(f);
      expect(exitCode).to.equal(0, "function param should not trigger AP-020");
    });

    it("event parameter 'uint64 amount' does NOT trigger AP-020", function () {
      const f = writeTmp("clean-event-amount.sol", `${PREAMBLE}
import "@openzeppelin/contracts/access/Ownable.sol";
contract Clean3 is ZamaEthereumConfig, Ownable {
    event Mint(address indexed to, uint64 amount);
    mapping(address => euint64) private _b;
    constructor() Ownable(msg.sender) {}
    function deposit(externalEuint64 enc, bytes calldata proof) external {
        _b[msg.sender] = FHE.fromExternal(enc, proof);
        FHE.allowThis(_b[msg.sender]);
        FHE.allow(_b[msg.sender], msg.sender);
    }
    function mint(address to, uint64 amount) external onlyOwner {
        _b[to] = FHE.add(_b[to], FHE.asEuint64(amount));
        FHE.allowThis(_b[to]);
        FHE.allow(_b[to], to);
        emit Mint(to, amount);
    }
}
`);
      const { exitCode } = runLinter(f);
      expect(exitCode).to.equal(0, "event param should not trigger AP-020");
    });
  });

  // -------------------------------------------------------------------------
  // AP-003 clean: allowThis in vicinity suppresses the rule
  // -------------------------------------------------------------------------
  describe("AP-003 clean: FHE.allowThis within 5 lines suppresses the rule", function () {
    it("state write immediately followed by FHE.allowThis does NOT trigger AP-003", function () {
      const f = writeTmp("clean-ap003.sol", `${PREAMBLE}
import "@openzeppelin/contracts/access/Ownable.sol";
contract Clean4 is ZamaEthereumConfig, Ownable {
    mapping(address => euint64) private _b;
    constructor() Ownable(msg.sender) {}
    function store(externalEuint64 enc, bytes calldata proof) external {
        _b[msg.sender] = FHE.fromExternal(enc, proof);
        FHE.allowThis(_b[msg.sender]);
        FHE.allow(_b[msg.sender], msg.sender);
    }
}
`);
      const { exitCode } = runLinter(f);
      expect(exitCode).to.equal(0, "AP-003 should not fire when allowThis is present");
    });
  });
});
