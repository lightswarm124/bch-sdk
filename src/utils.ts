import { 
  cashAddressToLockingBytecode,
  decodeCashAddress,
  addressContentsToLockingBytecode,
  lockingBytecodeToCashAddress,
  binToHex,
  Transaction,
  generateSigningSerializationBCH,
  utf8ToBin,
  hexToBin,
  flattenBinArray,
  LockingBytecodeType,
  encodeTransactionOutput,
  isHex,
  //bigIntToCompactSize,
  hash160,
  hash256,
} from "@bitauth/libauth";
import { 
  Op,
  Script, 
  scriptToBytecode
} from "./utils/script.js";
import { encodeInt } from "./utils/data.js";
import {
  Utxo,
  Output,
  Network,
  LibauthOutput,
} from './interfaces.js';
import { VERSION_SIZE, LOCKTIME_SIZE } from './constants.js';
import {
  OutputSatoshisTooSmallError,
  TokensToNonTokenAddressError,
  Reason,
  FailedTransactionError,
  FailedRequireError,
  FailedTimeCheckError,
  FailedSigCheckError,
} from './Errors.js';

// ////////// PFrom @bitauth/libauth v2.0.0-alpha.8 ///////////

const enum CompactSize {
  uint8MaxValue = 0xfc,
  uint16Prefix = 0xfd,
  uint16MaxValue = 0xffff,
  uint32Prefix = 0xfe,
  uint32MaxValue = 0xffffffff,
  uint64Prefix = 0xff,
  uint8 = 1,
  uint16 = 2,
  uint32 = 4,
  uint64 = 8,
}

export const binToFixedLength = (bin: Uint8Array, bytes: number) => {
  const fixedBytes = new Uint8Array(bytes);
  const maxValue = 255;
  // eslint-disable-next-line functional/no-expression-statement
  bin.length > bytes ? fixedBytes.fill(maxValue) : fixedBytes.set(bin);
  return fixedBytes;
};

const numberToBinUint16LE = (value: number) => {
  const uint16Length = 2;
  const bin = new Uint8Array(uint16Length);
  const writeAsLittleEndian = true;
  const view = new DataView(bin.buffer, bin.byteOffset, bin.byteLength);
  // eslint-disable-next-line functional/no-expression-statement
  view.setUint16(0, value, writeAsLittleEndian);
  return bin;
};

const numberToBinUint32LE = (value: number) => {
  const uint32Length = 4;
  const bin = new Uint8Array(uint32Length);
  const writeAsLittleEndian = true;
  const view = new DataView(bin.buffer, bin.byteOffset, bin.byteLength);
  // eslint-disable-next-line functional/no-expression-statement
  view.setUint32(0, value, writeAsLittleEndian);
  return bin;
};

const numberToBinUint32BE = (value: number) => {
  const uint32Length = 4;
  const bin = new Uint8Array(uint32Length);
  const writeAsLittleEndian = false;
  const view = new DataView(bin.buffer, bin.byteOffset, bin.byteLength);
  // eslint-disable-next-line functional/no-expression-statement
  view.setUint32(0, value, writeAsLittleEndian);
  return bin;
};

/**
 * Encode a positive BigInt as little-endian Uint8Array. Negative values will
 * return the same result as `0`.
 *
 * @param value - the number to encode
 */
export const bigIntToBinUintLE = (value: bigint) => {
  const baseUint8Array = 256;
  const base = BigInt(baseUint8Array);
  const result: number[] = [];
  // eslint-disable-next-line functional/no-let
  let remaining = value;
  // eslint-disable-next-line functional/no-loop-statement
  while (remaining >= base) {
    // eslint-disable-next-line functional/no-expression-statement, functional/immutable-data
    result.push(Number(remaining % base));
    // eslint-disable-next-line functional/no-expression-statement
    remaining /= base;
  }
  // eslint-disable-next-line functional/no-conditional-statement, functional/no-expression-statement, functional/immutable-data
  if (remaining > 0n) result.push(Number(remaining));

  return Uint8Array.from(result.length > 0 ? result : [0]);
};

/**
 * Encode a positive BigInt as an 8-byte Uint64LE Uint8Array, clamping the
 * results – values exceeding `0xffff_ffff_ffff_ffff` (`18446744073709551615`)
 * return the same result as `0xffff_ffff_ffff_ffff`, negative values return the
 * same result as `0`.
 *
 * @param value - the number to encode
 */
export const bigIntToBinUint64LEClamped = (value: bigint) => {
  const uint64 = 8;
  return binToFixedLength(bigIntToBinUintLE(value), uint64);
};

/**
 * Encode a positive BigInt as an 8-byte Uint64LE Uint8Array.
 *
 * This method will return an incorrect result for values outside of the range
 * `0` to `0xffff_ffff_ffff_ffff` (`18446744073709551615`).
 *
 * @param value - the number to encode
 */
export const bigIntToBinUint64LE = (value: bigint) => {
  const uint64LengthInBits = 64;
  const valueAsUint64 = BigInt.asUintN(uint64LengthInBits, value);
  const fixedLengthBin = bigIntToBinUint64LEClamped(valueAsUint64);
  return fixedLengthBin;
};

/**
 * Encode a positive BigInt as a `CompactSize` (Satoshi's variable-length,
 * positive integer format).
 *
 * Note: the maximum value of a CompactSize is `0xffff_ffff_ffff_ffff`
 * (`18446744073709551615`). This method will return an incorrect result for
 * values outside of the range `0` to `0xffff_ffff_ffff_ffff`. If applicable,
 * applications should handle such cases prior to calling this method.
 *
 * @param value - the BigInt to encode (must be no larger than
 * `0xffff_ffff_ffff_ffff`)
 */
export const bigIntToCompactSize = (value: bigint) =>
  value <= BigInt(CompactSize.uint8MaxValue)
    ? Uint8Array.of(Number(value))
    : value <= BigInt(CompactSize.uint16MaxValue)
    ? Uint8Array.from([
        CompactSize.uint16Prefix,
        ...numberToBinUint16LE(Number(value)),
      ])
    : value <= BigInt(CompactSize.uint32MaxValue)
    ? Uint8Array.from([
        CompactSize.uint32Prefix,
        ...numberToBinUint32LE(Number(value)),
      ])
    : Uint8Array.from([
        CompactSize.uint64Prefix,
        ...bigIntToBinUint64LE(value),
      ]);

// ////////// PARAMETER VALIDATION ////////////////////////////////////////////
export function validateOutput(output: Output): void {
  if (typeof output.to !== 'string') return;

  const minimumAmount = calculateDust(output);
  if (output.amount < minimumAmount) {
    throw new OutputSatoshisTooSmallError(output.amount, BigInt(minimumAmount));
  }

  if (output.token) {
    if (!isTokenAddress(output.to)) {
      throw new TokensToNonTokenAddressError(output.to);
    }
  }
}

export function calculateDust(output: Output): number {
  const outputSize = getOutputSize(output);
  // Formula used to calculate the minimum allowed output
  const dustAmount = 444 + outputSize * 3;
  return dustAmount;
}

export function getOutputSize(output: Output): number {
  const encodedOutput = encodeOutput(output);
  return encodedOutput.byteLength;
}

export function encodeOutput(output: Output): Uint8Array {
  return encodeTransactionOutput(cashScriptOutputToLibauthOutput(output));
}

export function cashScriptOutputToLibauthOutput(output: Output): LibauthOutput {
  if (output.token) {
    if (typeof output.token.category !== 'string' || !isHex(output.token.category)) {
      throw new Error(`Provided token category ${output.token?.category} is not a hex string`);
    }

    if (output.token.nft && (typeof output.token.nft.commitment !== 'string' || !isHex(output.token.nft.commitment))) {
      throw new Error(`Provided token commitment ${output.token.nft?.commitment} is not a hex string`);
    }
  }

  return {
    lockingBytecode: typeof output.to === 'string' ? addressToLockScript(output.to) : output.to,
    valueSatoshis: output.amount,
    token: output.token && {
      ...output.token,
      category: hexToBin(output.token.category),
      nft: output.token.nft && {
        ...output.token.nft,
        commitment: hexToBin(output.token.nft.commitment),
      },
    },
  };
}

export function libauthOutputToCashScriptOutput(output: LibauthOutput): Output {
  return {
    to: output.lockingBytecode,
    amount: output.valueSatoshis,
    token: output.token && {
      ...output.token,
      category: binToHex(output.token.category),
      nft: output.token.nft && {
        ...output.token.nft,
        commitment: binToHex(output.token.nft.commitment),
      },
    },
  };
}

function isTokenAddress(address: string): boolean {
  const result = decodeCashAddress(address);
  if (typeof result === 'string') throw new Error(result);
  const supportsTokens = (result.type === 'p2pkhWithTokens' || result.type === 'p2shWithTokens');
  return supportsTokens;
}

// ////////// SIZE CALCULATIONS ///////////////////////////////////////////////
export function getInputSize(inputScript: Uint8Array): number {
  const scriptSize = inputScript.byteLength;
  const varIntSize = scriptSize > 252 ? 3 : 1;
  return 32 + 4 + varIntSize + scriptSize + 4;
}

export function getPreimageSize(script: Uint8Array): number {
  const scriptSize = script.byteLength;
  const varIntSize = scriptSize > 252 ? 3 : 1;
  return 4 + 32 + 32 + 36 + varIntSize + scriptSize + 8 + 4 + 32 + 4 + 4;
}

export function getTxSizeWithoutInputs(outputs: Output[]): number {
  // Transaction format:
  // Version (4 Bytes)
  // TxIn Count (1 ~ 9B)
  // For each TxIn:
  //   Outpoint (36B)
  //   Script Length (1 ~ 9B)
  //   ScriptSig(?)
  //   Sequence (4B)
  // TxOut Count (1 ~ 9B)
  // For each TxOut:
  //   Value (8B)
  //   Script Length(1 ~ 9B)*
  //   Script (?)*
  // LockTime (4B)

  let size = VERSION_SIZE + LOCKTIME_SIZE;
  size += outputs.reduce((acc, output) => acc + getOutputSize(output), 0);
  // Add tx-out count (accounting for a potential change output)
  size += bigIntToCompactSize(BigInt(outputs.length + 1)).byteLength;

  return size;
}

// ////////// BUILD OBJECTS ///////////////////////////////////////////////////
export function createInputScript(
  redeemScript: Script,
  encodedArgs: Uint8Array[],
  selector?: number,
  preimage?: Uint8Array,
): Uint8Array {
  // Create unlock script / redeemScriptSig (add potential preimage and selector)
  const unlockScript = encodedArgs.reverse();
  if (preimage !== undefined) unlockScript.push(preimage);
  if (selector !== undefined) unlockScript.push(encodeInt(BigInt(selector)));

  // Create input script and compile it to bytecode
  const inputScript = [...unlockScript, scriptToBytecode(redeemScript)];
  return scriptToBytecode(inputScript);
}

export function createOpReturnOutput(
  opReturnData: string[],
): Output {
  const script = [
    Op.OP_RETURN,
    ...opReturnData.map((output: string) => toBin(output)),
  ];

  return { to: encodeNullDataScript(script), amount: 0n };
}

function toBin(output: string): Uint8Array {
  const data = output.replace(/^0x/, '');
  const encode = data === output ? utf8ToBin : hexToBin;
  return encode(data);
}

export function createSighashPreimage(
  transaction: Transaction,
  sourceOutputs: LibauthOutput[],
  inputIndex: number,
  coveredBytecode: Uint8Array,
  hashtype: number,
): Uint8Array {
  const context = { inputIndex, sourceOutputs, transaction };
  const signingSerializationType = new Uint8Array([hashtype]);

  const sighashPreimage = generateSigningSerializationBCH(context, { coveredBytecode, signingSerializationType });

  return sighashPreimage;
}

export function buildError(reason: string, meepStr?: string): FailedTransactionError {
  const require = [
    Reason.EVAL_FALSE, Reason.VERIFY, Reason.EQUALVERIFY, Reason.CHECKMULTISIGVERIFY,
    Reason.CHECKSIGVERIFY, Reason.CHECKDATASIGVERIFY, Reason.NUMEQUALVERIFY,
  ];
  const timeCheck = [Reason.NEGATIVE_LOCKTIME, Reason.UNSATISFIED_LOCKTIME];
  const sigCheck = [
    Reason.SIG_COUNT, Reason.PUBKEY_COUNT, Reason.SIG_HASHTYPE, Reason.SIG_DER,
    Reason.SIG_HIGH_S, Reason.SIG_NULLFAIL, Reason.SIG_BADLENGTH, Reason.SIG_NONSCHNORR,
  ];

  if (toRegExp(require).test(reason)) {
    return new FailedRequireError(reason, meepStr);
  }

  if (toRegExp(timeCheck).test(reason)) {
    return new FailedTimeCheckError(reason, meepStr);
  }

  if (toRegExp(sigCheck).test(reason)) {
    return new FailedSigCheckError(reason, meepStr);
  }

  return new FailedTransactionError(reason, meepStr);
}

function toRegExp(reasons: string[]): RegExp {
  return new RegExp(reasons.join('|').replace(/\(/g, '\\(').replace(/\)/g, '\\)'));
}

// ////////// MISC ////////////////////////////////////////////////////////////
export function meep(tx: any, utxos: Utxo[], script: Script): string {
  const scriptPubkey = binToHex(scriptToLockingBytecode(script, 'p2sh20'));
  return `meep debug --tx=${tx} --idx=0 --amt=${utxos[0].satoshis} --pkscript=${scriptPubkey}`;
}

export function scriptToAddress(script: Script, network: string, addressType: 'p2sh20' | 'p2sh32', tokenSupport: boolean): string {
  const lockingBytecode = scriptToLockingBytecode(script, addressType);
  const prefix = getNetworkPrefix(network);
  const address = lockingBytecodeToCashAddress({
    bytecode: lockingBytecode,
    prefix,
    tokenSupport
  }) as string;
  return address;
}

export function scriptToLockingBytecode(script: Script, addressType: 'p2sh20' | 'p2sh32'): Uint8Array {
  const scriptBytecode = scriptToBytecode(script);
  const scriptHash = (addressType === 'p2sh20') ? hash160(scriptBytecode) : hash256(scriptBytecode);
  const addressContents = { payload: scriptHash, type: LockingBytecodeType[addressType] };
  const lockingBytecode = addressContentsToLockingBytecode(addressContents);
  return lockingBytecode;
}

export function publicKeyToP2PKHLockingBytecode(publicKey: Uint8Array): Uint8Array {
  const pubkeyHash = hash160(publicKey);
  const addressContents = { payload: pubkeyHash, type: LockingBytecodeType.p2pkh };
  const lockingBytecode = addressContentsToLockingBytecode(addressContents);
  return lockingBytecode;
}

export function utxoComparator(a: Utxo, b: Utxo): number {
  if (a.satoshis > b.satoshis) return 1;
  if (a.satoshis < b.satoshis) return -1;
  return 0;
}

export function utxoTokenComparator(a: Utxo, b: Utxo): number {
  if (!a.token || !b.token) throw new Error('UTXO does not have token data');
  if (!a.token.category !== !b.token.category) throw new Error('UTXO token categories do not match');
  if (a.token.amount > b.token.amount) return 1;
  if (a.token.amount < b.token.amount) return -1;
  return 0;
}

/**
* Helper function to convert an address to a locking script
*
* @param address   Address to convert to locking script
*
* @returns a locking script corresponding to the passed address
*/
export function addressToLockScript(address: string): Uint8Array {
  const result = cashAddressToLockingBytecode(address);

  if (typeof result === 'string') throw new Error(result);

  return result.bytecode;
}

export function getNetworkPrefix(network: string): 'bitcoincash' | 'bchtest' | 'bchreg' {
  switch (network) {
    case Network.MAINNET:
      return 'bitcoincash';
    case Network.TESTNET4:
    case Network.TESTNET3:
    case Network.CHIPNET:
      return 'bchtest';
    case Network.REGTEST:
      return 'bchreg';
    default:
      return 'bitcoincash';
  }
}

// ////////////////////////////////////////////////////////////////////////////
// For encoding OP_RETURN data (doesn't require BIP62.3 / MINIMALDATA)
function encodeNullDataScript(chunks: (number | Uint8Array)[]): Uint8Array {
  return flattenBinArray(
    chunks.map((chunk) => {
      if (typeof chunk === 'number') {
        return new Uint8Array([chunk]);
      }

      const pushdataOpcode = getPushDataOpcode(chunk);
      return new Uint8Array([...pushdataOpcode, ...chunk]);
    }),
  );
}

function getPushDataOpcode(data: Uint8Array): Uint8Array {
  const { byteLength } = data;

  if (byteLength === 0) return Uint8Array.from([0x4c, 0x00]);
  if (byteLength < 76) return Uint8Array.from([byteLength]);
  if (byteLength < 256) return Uint8Array.from([0x4c, byteLength]);
  throw Error('Pushdata too large');
}