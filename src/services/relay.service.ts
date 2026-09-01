import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545';
// Hardhat default account #0
const RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY || '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; 
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || '0x0000000000000000000000000000000000000000';

export class RelayService {
  private provider: ethers.JsonRpcProvider;
  private wallet: ethers.Wallet;
  private contract: ethers.Contract;

  constructor(
    rpcUrl: string = RPC_URL, 
    privateKey: string = RELAYER_PRIVATE_KEY, 
    contractAddress: string = CONTRACT_ADDRESS,
    injectedSigner?: ethers.Signer
  ) {
    if (injectedSigner) {
      this.provider = injectedSigner.provider as ethers.JsonRpcProvider;
      this.wallet = injectedSigner as any;
    } else {
      this.provider = new ethers.JsonRpcProvider(rpcUrl);
      this.wallet = new ethers.Wallet(privateKey, this.provider);
    }
    
    // Load ABI
    let abi: any[] = [];
    try {
      // Navigate up from src/services to the root where artifacts/ resides
      const artifactPath = path.resolve(__dirname, '../../artifacts/contracts/DocumentIssuanceConsortium.sol/DocumentIssuanceConsortium.json');
      if (fs.existsSync(artifactPath)) {
        const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
        abi = artifact.abi;
      } else {
        console.warn('Contract artifact not found. RelayService might fail if methods are called.');
      }
    } catch (e) {
      console.error('Failed to load contract ABI:', e);
    }

    this.contract = new ethers.Contract(contractAddress, abi, this.wallet);
  }

  /**
   * Invokes `issueDocument` on-chain (Issuer only).
   */
  async issueDocumentOnChain(docHash: string, citizenAddress: string, docType: string) {
    const tx = await this.contract.issueDocument(docHash, citizenAddress, docType);
    return await tx.wait();
  }

  /**
   * Invokes `uploadPersonalDocument` on-chain.
   * Allows gasless submission for citizens.
   */
  async uploadPersonalDocumentOnChain(docHash: string, docType: string) {
    const tx = await this.contract.uploadPersonalDocument(docHash, docType);
    return await tx.wait();
  }

  /**
   * Invokes `revokeDocument` on-chain (Issuer only).
   */
  async revokeDocumentOnChain(docHash: string) {
    const tx = await this.contract.revokeDocument(docHash);
    return await tx.wait();
  }

  /**
   * Queries the blockchain for a citizen's documents without incurring gas.
   */
  async getCitizenDocuments(citizenAddress: string): Promise<string[]> {
    return await this.contract.getCitizenDocuments(citizenAddress);
  }
}
