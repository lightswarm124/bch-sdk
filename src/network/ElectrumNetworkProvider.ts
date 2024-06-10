import { 
  binToHex,
  sha256,
} from '@bitauth/libauth';
import { 
  ElectrumClient, 
  ElectrumTransport,
  ClusterOrder,
  RequestResponse 
} from '@electrum-cash/network';
import { Utxo, Network } from '../interfaces.js';
import NetworkProvider from './NetworkProvider.js';
import { addressToLockScript } from '../utils.js';

// Note: ElectrumCluster is depreciated from @electrum-cash/network

export default class ElectrumNetworkProvider implements NetworkProvider {
  // pointer for current ElectrumClient instance
  private electrum: ElectrumClient | null = null;
  private concurrentRequests: number = 0;

  constructor(
    public network: Network = Network.MAINNET,
    electrum?: ElectrumClient,
    private manualConnectionManagement?: boolean,
  ) {
    // If a custom Electrum Cluster is passed, we use it instead of the default.
    if (electrum) {
      this.electrum = electrum;
      return;
    }
    
    if (network === Network.MAINNET) {
      this.electrum = new ElectrumClient(
        'CashScript Application', 
        '1.5.1', 
        'bch.imaginary.cash', 
        ElectrumTransport.WSS.Port,
        ElectrumTransport.WSS.Scheme
      );
    } else if (network === Network.CHIPNET) {
      this.electrum = new ElectrumClient(
        'CashScript Application',
        '1.5.1',
        'chipnet.imaginary.cash',
        ElectrumTransport.WSS.Port,
        ElectrumTransport.WSS.Scheme
      ) 
    } else {
      throw new Error(`Tried to instantiate an ElectrumNetworkProvider for unsupported network ${network}`);
    }
  }

  async getUtxos(address: string): Promise<Utxo[]> {
    const scripthash = addressToElectrumScriptHash(address);

    const filteringOption = 'include_tokens';
    const result = await this.performRequest('blockchain.scripthash.listunspent', scripthash, filteringOption) as ElectrumUtxo[];

    const utxos = result.map((utxo) => ({
      txid: utxo.tx_hash,
      vout: utxo.tx_pos,
      satoshis: BigInt(utxo.value),
      token: utxo.token_data ? {
        ...utxo.token_data,
        amount: BigInt(utxo.token_data.amount),
      } : undefined,
    }));

    return utxos;
  }

  async getBlockHeight(): Promise<number> {
    const { height } = await this.performRequest('blockchain.headers.subscribe') as BlockHeader;
    return height;
  }

  async getRawTransaction(txid: string): Promise<string> {
    return await this.performRequest('blockchain.transaction.get', txid) as string;
  }

  async sendRawTransaction(txHex: string): Promise<string> {
    return await this.performRequest('blockchain.transaction.broadcast', txHex) as string;
  }


  async connectClient(): Promise<void> {
    try {
      return await this.electrum!.connect();
    } catch (e) {
      return;
    }
  }

  async disconnectClient(): Promise<boolean> {
    return this.electrum!.disconnect();
  }

  async performRequest(
    name: string,
    ...parameters: (string | number | boolean)[]
  ): Promise<RequestResponse> {
    // Only connect the cluster when no concurrent requests are running
    if (this.shouldConnect()) {
      this.connectClient();
    }

    this.concurrentRequests += 1;

    let result;
    try {
      result = await this.electrum!.request(name, ...parameters);
    } finally {
      // Always disconnect the cluster, also if the request fails
      // as long as no other concurrent requests are running
      if (this.shouldDisconnect()) {
        await this.disconnectClient();
      }
    }

    this.concurrentRequests -= 1;

    if (result instanceof Error) throw result;

    return result;
  }

  private shouldConnect(): boolean {
    if (this.manualConnectionManagement) return false;
    if (this.concurrentRequests !== 0) return false;
    return true;
  }

  private shouldDisconnect(): boolean {
    if (this.manualConnectionManagement) return false;
    if (this.concurrentRequests !== 1) return false;
    return true;
  }
}

interface ElectrumUtxo {
  tx_pos: number;
  value: number;
  tx_hash: string;
  height: number;
  token_data?: {
    amount: string;
    category: string;
    nft?: {
      capability: 'none' | 'mutable' | 'minting';
      commitment: string;
    };
  };
}

interface BlockHeader {
  height: number;
  hex: string;
}

/**
 * Helper function to convert an address to an electrum-cash compatible scripthash.
 * This is necessary to support electrum versions lower than 1.4.3, which do not
 * support addresses, only script hashes.
 *
 * @param address Address to convert to an electrum scripthash
 *
 * @returns The corresponding script hash in an electrum-cash compatible format
 */
function addressToElectrumScriptHash(address: string): string {
  // Retrieve locking script
  const lockScript = addressToLockScript(address);

  // Hash locking script
  const initSha256 = sha256.init()
  const scriptHash = sha256.update(initSha256, lockScript);

  // Reverse scripthash
  scriptHash.reverse();

  // Return scripthash as a hex string
  return binToHex(scriptHash);
}