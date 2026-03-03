/**
 * ERC-1271 × Alchemy Light Account × Pimlico Bundler
 * ─────────────────────────────────────────────────────
 * Tests ERC-7562 compliance against EntryPoint v0.7.
 *
 * The Light Account owner is set to your ERC-1271 contract.
 * On validation, the EntryPoint calls:
 *   isValidSignature(userOpHash, encodedSigs)
 * on that contract, where encodedSigs is the concatenation of the three
 * private-key signers' ECDSA signatures, sorted by signer address.
 *
 * ⚠️  encodeMultiSigSignature() must match your contract's expected format.
 *
 * Usage:
 *   cp .env.example .env   # fill in your values
 *   npm install && npm test
 */

import "dotenv/config";
import {
  createPublicClient,
  http,
  type Address,
  type Hex,
  concat,
  getAddress,
  hashTypedData,
  zeroAddress,
  fromHex,
  hexToBytes,
  toHex,
  bytesToHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia, mainnet, holesky } from "viem/chains";
import type { Chain, LocalAccount } from "viem";
import { createSmartAccountClient } from "permissionless";
import { toLightSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";

// ─── EntryPoint v0.7 address ──────────────────────────────────────────────────
// Verify this against:
//   https://github.com/eth-infinitism/account-abstraction/releases
// before using on a live network.
const ENTRY_POINT_V07_ADDRESS: Address =
  "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

// ─── Config from env ──────────────────────────────────────────────────────────
function requireEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`Missing env var: ${key}`);
  return v;
}

const CHAIN_NAME            = (process.env.CHAIN ?? "sepolia").toLowerCase();
const ALCHEMY_RPC_URL       = requireEnv("ALCHEMY_RPC_URL");
const PIMLICO_API_KEY       = requireEnv("PIMLICO_API_KEY");
const ERC1271_ADDRESS       = getAddress(requireEnv("ERC1271_CONTRACT_ADDRESS"));
const SIGNER1_PK            = requireEnv("SIGNER1_PRIVATE_KEY").startsWith("0x") ? requireEnv("SIGNER1_PRIVATE_KEY") as Hex : `0x${requireEnv("SIGNER1_PRIVATE_KEY")}` as Hex;
const SIGNER2_PK            = requireEnv("SIGNER2_PRIVATE_KEY").startsWith("0x") ? requireEnv("SIGNER2_PRIVATE_KEY") as Hex : `0x${requireEnv("SIGNER2_PRIVATE_KEY")}` as Hex;
const SIGNER3_PK            = requireEnv("SIGNER3_PRIVATE_KEY").startsWith("0x") ? requireEnv("SIGNER3_PRIVATE_KEY") as Hex : `0x${requireEnv("SIGNER3_PRIVATE_KEY")}` as Hex;
const USE_PAYMASTER         = process.env.USE_PAYMASTER === "true";

function resolveChain(name: string): Chain {
  const map: Record<string, Chain> = { sepolia, mainnet, holesky };
  const chain = map[name];
  if (!chain) throw new Error(`Unsupported CHAIN="${name}".`);
  return chain;
}

function pimlicoBundlerUrl(chain: Chain): string {
  return `https://api.pimlico.io/v2/${chain.name.toLowerCase()}/rpc?apikey=${PIMLICO_API_KEY}`;
}

// ─── Multi-sig signature encoder ─────────────────────────────────────────────
//
// Default: sort signers by address (ascending), then concatenate 65-byte sigs.
//
// ⚠️  ADAPT THIS to match your ERC-1271 contract's isValidSignature encoding.
//     Common alternatives:
//       • ABI-encoded array:   abi.encode(sig1, sig2, sig3)
//       • Length-prefixed:     abi.encode(uint8(3), sig1, sig2, sig3)
//       • Custom struct
//
function encodeMultiSigSignature(
  sigs: { address: Address; sig: Hex }[]
): Hex {
  const sorted = [...sigs].sort((a, b) =>
    a.address.toLowerCase().localeCompare(b.address.toLowerCase()),
  );
  
  console.log(`🔍  Encoding ${sorted.length} signatures:`);
  sorted.forEach(({ address, sig }, i) => {
    const sigBytes = (sig.length - 2) / 2;
    console.log(`    [${i + 1}] ${address}: ${sig} (${sigBytes} bytes)`);
  });
  
  // Use concat instead of manual byte manipulation to avoid padding issues
  const encoded = concat(sorted.map(({ sig }) => sig));
  
  console.log(`🔍  Final encoded signature: ${encoded} (${(encoded.length - 2) / 2} bytes)`);
  
  return encoded;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const chain = resolveChain(CHAIN_NAME);

  console.log("\n══════════════════════════════════════════════════");
  console.log("  ERC-1271 × Light Account × Pimlico — EP v0.7");
  console.log("══════════════════════════════════════════════════");
  console.log(`  Chain      : ${chain.name} (id ${chain.id})`);
  console.log(`  EntryPoint : ${ENTRY_POINT_V07_ADDRESS}`);
  console.log(`  Validator  : ${ERC1271_ADDRESS}`);
  console.log("══════════════════════════════════════════════════\n");

  // ── 1. Three deterministic signers from private keys ─────────────────────
  console.log("🔐  Setting up signers from private keys…");
  const signer1 = privateKeyToAccount(SIGNER1_PK);
  const signer2 = privateKeyToAccount(SIGNER2_PK);
  const signer3 = privateKeyToAccount(SIGNER3_PK);
  const allSigners = [signer1, signer2]; //, signer3];  # 2-of-3 example;

  console.log("👥  Signers:");
  allSigners.forEach((s, i) => console.log(`    [${i + 1}] ${s.address}`));
  console.log();

  // ── 2. Public + bundler clients ───────────────────────────────────────────
  const publicClient = createPublicClient({
    chain,
    transport: http(ALCHEMY_RPC_URL),
  });

  const bundlerClient = createPimlicoClient({
    transport: http(pimlicoBundlerUrl(chain)),
    entryPoint: {
      address: ENTRY_POINT_V07_ADDRESS,
      version: "0.7",
    },
  });

  // ── 3. ERC-1271 composite signer ─────────────────────────────────────────
  //
  //  We set `address` to the ERC-1271 contract so that it becomes the
  //  on-chain owner of the Light Account.  When the SDK calls signMessage /
  //  signTypedData, we fan out to all three private keys and encode the sigs.
  //
  const erc1271Signer = {
    type: "local" as const,
    address: ERC1271_ADDRESS,

    async signMessage({
      message,
    }: {
      message: string | { raw: Hex };
    }): Promise<Hex> {
      const rawHash: Hex =
        typeof message === "string" ? (message as Hex) : message.raw;

      console.log(`🔍  Signing UserOp hash: ${rawHash}`);
      console.log(`🔍  Using ${allSigners.length} signers for multi-sig`);
      const collected = await Promise.all(
        allSigners.map(async (s) => ({
          address: s.address,
          sig: await s.sign({ hash: rawHash }),
        }))
      );

      console.log(`🔍  Individual signatures:`);
      collected.forEach(({ address, sig }, i) => {
        const sigLength = (sig.length - 2) / 2; // Convert hex length to bytes
        console.log(`    [${i + 1}] ${address}: ${sig} (${sigLength} bytes)`);
      });
      
      const encoded = encodeMultiSigSignature(collected);
      console.log(`🔍  Encoded multi-sig (${allSigners.length} signers, ${(encoded.length - 2) / 2} bytes):`);
      console.log(`    ${encoded}`);
      return encoded as Hex;
    },

    async signTypedData(params: {
      domain: Record<string, unknown>;
      types: Record<string, unknown>;
      primaryType: string;
      message: Record<string, unknown>;
    }): Promise<Hex> {
      const finalHash = hashTypedData({
        domain: params.domain as Parameters<typeof hashTypedData>[0]["domain"],
        types: params.types as Parameters<typeof hashTypedData>[0]["types"],
        primaryType: params.primaryType,
        message: params.message as Parameters<typeof hashTypedData>[0]["message"],
     });
      const collected = await Promise.all(
        allSigners.map(async (s) => ({
          address: s.address,
          sig: await s.sign({ hash: finalHash }),
        }))
      );
      console.log(`🔍  Typed data individual signatures:`);
      collected.forEach(({ address, sig }, i) => {
        const sigLength = (sig.length - 2) / 2; // Convert hex length to bytes
        console.log(`    [${i + 1}] ${address}: ${sig} (${sigLength} bytes)`);
      });
      return encodeMultiSigSignature(collected);
    },
  };

  // ── 4. Derive Light Account address ──────────────────────────────────────
  console.log("⚙️   Building Light Account…");

  const lightAccount = await toLightSmartAccount({
    client: publicClient,
    owner: erc1271Signer as LocalAccount,
    version: "2.0.0",
    entryPoint: {
      address: ENTRY_POINT_V07_ADDRESS,
      version: "0.7",
    },
  });

  const saAddress = lightAccount.address;
  console.log(`📬  Smart Account : ${saAddress}`);

  const balance = await publicClient.getBalance({ address: saAddress });
  console.log(`💰  Balance       : ${balance} wei`);

  if (!USE_PAYMASTER && balance === 0n) {
    console.warn(
      `\n⚠️  Smart account has no ETH.\n` +
      `   Fund ${saAddress} or set USE_PAYMASTER=true.\n`
    );
  }

  // ── 5. Smart Account client ───────────────────────────────────────────────
  const smartAccountClient = createSmartAccountClient({
    account: lightAccount,
    bundlerTransport: http(pimlicoBundlerUrl(chain)),
    // Uncomment to add Pimlico paymaster sponsorship:
    // paymaster: createPaymasterClient({ transport: http(pimlicoBundlerUrl(chain)) }),
    userOperation: {
      estimateFeesPerGas: async () =>
        (await bundlerClient.getUserOperationGasPrice()).fast,
    },
  });

  // ── 6. Define the call  ──────────────────────────────────────────────────
  //
  //  Default is a 0-ETH no-op that exercises the full validation path.
  //  Replace TARGET_ADDRESS / CALL_VALUE / CALL_DATA for your real test.
  //
  const TARGET_ADDRESS: Address = zeroAddress; // ← your target
  const CALL_VALUE               = 0n;          // ← wei
  const CALL_DATA: Hex           = "0x";        // ← ABI-encoded calldata

  console.log("\n📋  UserOp call:");
  console.log(`    to      : ${TARGET_ADDRESS}`);
  console.log(`    value   : ${CALL_VALUE} wei`);
  console.log(`    calldata: ${CALL_DATA}`);

  // ── 7. Submit the UserOp ──────────────────────────────────────────────────
  let userOpHash: Hex;
  try {
    console.log("\n🚀  Submitting UserOp to Pimlico…");
    userOpHash = await smartAccountClient.sendUserOperation({
      account: lightAccount,
      calls: [{ to: TARGET_ADDRESS, value: CALL_VALUE, data: CALL_DATA }],
    });
    console.log(`    Hash : ${userOpHash}`);
  } catch (err) {
    console.error("\n❌  Failed to submit UserOp:");
    printError(err);
    process.exit(1);
  }

  // ── 8. Wait for receipt ───────────────────────────────────────────────────
  console.log("\n⏳  Waiting for on-chain confirmation (up to 2 min)…");
  try {
    const receipt = await bundlerClient.waitForUserOperationReceipt({
      hash: userOpHash,
      timeout: 120_000,
    });

    const { success, reason, logs, receipt: txReceipt } = receipt;
    console.log("\n──────────────────────────────────────────────────");
    if (success) {
      console.log("🎉  UserOp SUCCEEDED");
      console.log(`    Tx hash  : ${txReceipt.transactionHash}`);
      console.log(`    Block    : ${txReceipt.blockNumber}`);
      console.log(`    Gas used : ${txReceipt.gasUsed}`);
    } else {
      console.error("💥  UserOp FAILED");
      if (reason) {
        console.error(`\n    Revert reason : ${reason}`);
        const decoded = decodeAaError(reason);
        if (decoded) {
          console.error(`    AA error code : ${decoded.code}`);
          console.error(`    Description   : ${decoded.description}`);
          if (decoded.code === "AA23") {
            console.error(`\n💡  AA23 Troubleshooting:`);
            console.error(`    • Verify your ERC-1271 contract expects ${allSigners.length} signatures`);
            console.error(`    • Check signature encoding format in encodeMultiSigSignature()`);
            console.error(`    • Ensure signer addresses match contract's expected signers`);
            console.error(`    • Verify the userOp hash being signed is correct`);
            
            // Try to decode ERC-1271 specific error
            const erc1271Error = decodeErc1271Error(reason);
            if (erc1271Error) {
              console.error(`\n🔍  ERC-1271 Error Details:`);
              console.error(`    • Function selector: ${erc1271Error.selector}`);
              console.error(`    • Error code: ${erc1271Error.errorCode} (0x${erc1271Error.errorCode.toString(16)})`);
              if (erc1271Error.errorCode === 130) {
                console.error(`    • Error 130 often indicates signature count mismatch or invalid encoding`);
              }
            }
          }
        }
      }
      console.error(`\n    Tx hash  : ${txReceipt.transactionHash}`);
      console.error(`    Block    : ${txReceipt.blockNumber}`);
      if (logs.length) {
        console.error("\n    Event logs:");
        logs.forEach((l, i) => {
          console.error(`      [${i}] address : ${l.address}`);
          console.error(`           topics  : ${JSON.stringify(l.topics)}`);
          console.error(`           data    : ${l.data}`);
        });
      }
      console.log("──────────────────────────────────────────────────\n");
      process.exit(1);
    }
    console.log("──────────────────────────────────────────────────\n");
  } catch (err) {
    console.error("\n❌  Error waiting for receipt:");
    printError(err);
    process.exit(1);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function printError(err: unknown): void {
  if (err instanceof Error) {
    console.error(`   ${err.message}`);
    const e = err as Record<string, unknown>;
    if (e["details"]) console.error("   details :", e["details"]);
    if (e["cause"])   printError(e["cause"]);
  } else {
    console.error(err);
  }
}

/** Decode ERC-4337 / ERC-7562 AA error codes from a revert reason string. */
function decodeAaError(
  reason: string
): { code: string; description: string } | null {
  const AA_CODES: Record<string, string> = {
    AA10: "Sender already constructed — initCode must be empty",
    AA13: "initCode failed or OOG during deployment",
    AA14: "initCode must return the sender address",
    AA15: "initCode must not deploy more than one account",
    AA20: "Account not deployed and no initCode provided",
    AA21: "Account didn't pay prefund (balance too low)",
    AA22: "Account returned invalid nonce",
    AA23: "validateUserOp reverted — check your ERC-1271 sig encoding",
    AA24: "Signature expired or not yet valid",
    AA25: "Invalid account nonce",
    AA26: "Over verificationGasLimit",
    AA30: "Paymaster not deployed or not staked",
    AA31: "Paymaster deposit too low",
    AA32: "validatePaymasterUserOp reverted",
    AA33: "validatePaymasterUserOp OOG",
    AA34: "Paymaster signature expired or not yet valid",
    AA40: "callGasLimit too low",
    AA41: "Too little gas for postOp",
    AA50: "postOp reverted",
    AA51: "prefund below actualGasCost",
    AA80: "Unstaked entity violated ERC-7562 storage/opcode rules",
    AA90: "Internal EntryPoint error",
    AA95: "Out of gas",
    AA96: "Invalid aggregator",
    AA97: "Signature aggregation failed",
  };

  const match = reason.match(/\bAA\d{2}\b/);
  if (!match) return null;
  const code = match[0];
  return { code, description: AA_CODES[code] ?? "Unknown AA error" };
}

/** Decode specific ERC-1271 validation errors from revert data. */
function decodeErc1271Error(reason: string): { selector: string; errorCode: number } | null {
  // Look for hex data pattern like: 0xfce698f7...
  const hexMatch = reason.match(/0x([a-fA-F0-9]+)/);
  if (!hexMatch) return null;
  
  const hexData = hexMatch[1];
  if (hexData.length < 8) return null;
  
  const selector = `0x${hexData.slice(0, 8)}`;
  if (hexData.length >= 72) { // 8 chars selector + 64 chars for uint256
    const errorCodeHex = hexData.slice(-8); // Last 8 chars for error code
    const errorCode = parseInt(errorCodeHex, 16);
    return { selector, errorCode };
  }
  
  return { selector, errorCode: 0 };
}

main().catch((err) => {
  console.error("\n💀  Unhandled error:");
  printError(err);
  process.exit(1);
});