import bip68 from 'bip68';
import { 
  decodeTransaction, 
  hexToBin,
  Transaction as LibauthTransaction, 
} from '@bitauth/libauth';
import delay from 'delay';
import SignatureTemplate from "./SignatureTemplate";
import deepEqual from 'fast-deep-equal';
import { 
  isUtxoP2PKH,
  NftObject,
  Output, 
  Recipient, 
  TokenDetails, 
  TransactionDetails, 
  Unlocker, 
  Utxo 
} from "./interfaces";
import { 
  buildError,
  calculateDust,
  createInputScript,
  createOpReturnOutput, 
  getInputSize, 
  getOutputSize, 
  getPreimageSize, 
  getTxSizeWithoutInputs, 
  meep, 
  utxoComparator, 
  utxoTokenComparator, 
  validateOutput 
} from "./utils";
import { AbiFunction } from "./utils/artifact";
// import { Contract } from './Contract';
import { TransactionBuilder } from './TransactionBuilder';
import { placeholder } from './utils/data';
import { scriptToBytecode } from './utils/script';
import { P2PKH_INPUT_SIZE } from './constants';
import { NetworkProvider } from './network';

export class RegularTransaction {
  private inputs: Utxo[] = [];
  private outputs: Output[] = [];

  private sequence = 0xfffffffe;
  private locktime!: number;
  private feePerByte: number = 1.0;
  private hardcodedFee!: bigint;
  private minChange: bigint = 0n;
  private tokenChange: boolean = true;

  constructor(
    private provider: NetworkProvider,
    private unlocker: Unlocker,
    private abiFunction: AbiFunction,
    private args: (Uint8Array | SignatureTemplate)[],
    private selector?: number,
  ) {
    this.provider = provider;
  }

  from(input: Utxo): this;
  from(inputs: Utxo[]): this;

  from(inputOrInputs: Utxo | Utxo[]): this {
    if (!Array.isArray(inputOrInputs)) {
      inputOrInputs = [inputOrInputs];
    }

    this.inputs = this.inputs.concat(inputOrInputs);

    return this;
  }

  fromP2PKH(input: Utxo, template: SignatureTemplate): this;
  fromP2PKH(inputs: Utxo[], template: SignatureTemplate): this;

  fromP2PKH(inputOrInputs: Utxo | Utxo[], template: SignatureTemplate): this {
    if (!Array.isArray(inputOrInputs)) {
      inputOrInputs = [inputOrInputs];
    }

    inputOrInputs = inputOrInputs.map((input) => ({ ...input, template }));

    this.inputs = this.inputs.concat(inputOrInputs);

    return this;
  }

  to(to: string, amount: bigint, token?: TokenDetails): this;
  to(outputs: Recipient[]): this;

  to(toOrOutputs: string | Recipient[], amount?: bigint, token?: TokenDetails): this {
    if (typeof toOrOutputs === 'string' && typeof amount === 'bigint') {
      const recipient = { to: toOrOutputs, amount, token };
      return this.to([recipient]);
    }

    if (Array.isArray(toOrOutputs) && amount === undefined) {
      toOrOutputs.forEach(validateOutput);
      this.outputs = this.outputs.concat(toOrOutputs);
      return this;
    }

    throw new Error('Incorrect arguments passed to function \'to\'');
  }

  withOpReturn(chunks: string[]): this {
    this.outputs.push(createOpReturnOutput(chunks));
    return this;
  }

  withAge(age: number): this {
    this.sequence = bip68.encode({ blocks: age });
    return this;
  }

  withTime(time: number): this {
    this.locktime = time;
    return this;
  }

  withHardcodedFee(hardcodedFee: bigint): this {
    this.hardcodedFee = hardcodedFee;
    return this;
  }

  withFeePerByte(feePerByte: number): this {
    this.feePerByte = feePerByte;
    return this;
  }

  withMinChange(minChange: bigint): this {
    this.minChange = minChange;
    return this;
  }

  withoutChange(): this {
    return this.withMinChange(BigInt(Number.MAX_VALUE));
  }

  withoutTokenChange(): this {
    this.tokenChange = false;
    return this;
  }

  private async getTxDetails(txid: string): Promise<TransactionDetails>
  private async getTxDetails(txid: string, raw: true): Promise<string>;

  private async getTxDetails(txid: string, raw?: true): Promise<TransactionDetails | string> {
    for (let retries = 0; retries < 1200; retries += 1) {
      await delay(500);
      try {
        const hex = await this.provider.getRawTransaction(txid);

        if (raw) return hex;

        const libauthTransaction = decodeTransaction(hexToBin(hex)) as LibauthTransaction;
        return { ...libauthTransaction, txid, hex };
      } catch (ignored) {
        // ignored
      }
    }

    // Should not happen
    throw new Error('Could not retrieve transaction details for over 10 minutes');
  }
}