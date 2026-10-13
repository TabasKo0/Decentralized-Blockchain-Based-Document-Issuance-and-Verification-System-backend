import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class RelayerService {
  private provider: ethers.JsonRpcProvider;
  private wallet: ethers.Wallet;
  private contract: ethers.Contract;

  /**
   * Safely formats the private key ensuring the leading '0x' prefix is present.
   */
  private static formatPrivateKey(key?: string): string {
    const rawKey = key || process.env.SEPOLIA_PRIVATE_KEY || '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
    const trimmed = rawKey.trim();
    return trimmed.startsWith('0x') ? trimmed : `0x${trimmed}`;
  }

  constructor(
    rpcUrl: string = process.env.SEPOLIA_RPC_URL || process.env.RPC_URL || 'http://127.0.0.1:8545',
    privateKey?: string,
    contractAddress: string = process.env.CONTRACT_ADDRESS || '0x0000000000000000000000000000000000000000',
    injectedSigner?: ethers.Signer
  ) {
    if (injectedSigner) {
      this.provider = injectedSigner.provider as ethers.JsonRpcProvider;
      this.wallet = injectedSigner as any;
    } else {
      const formattedKey = RelayerService.formatPrivateKey(privateKey);
      this.provider = new ethers.JsonRpcProvider(rpcUrl);
      this.wallet = new ethers.Wallet(formattedKey, this.provider);
    }

    // Load ABI from compiled hardhat artifacts
    let abi: any[] = [];
    try {
      const artifactPath = path.resolve(
        __dirname,
        '../../artifacts/contracts/DocumentIssuanceConsortium.sol/DocumentIssuanceConsortium.json'
      );
      if (fs.existsSync(artifactPath)) {
        const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
        abi = artifact.abi;
      } else {
        console.warn('Contract artifact not found at:', artifactPath);
      }
    } catch (e) {
      console.error('Failed to load contract ABI in RelayerService:', e);
    }

    this.contract = new ethers.Contract(contractAddress, abi, this.wallet);
  }

  /**
   * Formats a document hash into a standard bytes32 hex string.
   */
  private static formatBytes32(hash: string): string {
    let clean = hash.trim();
    if (!clean.startsWith('0x')) {
      clean = `0x${clean}`;
    }
    if (clean.length !== 66) {
      throw new Error(`Invalid bytes32 hash length: expected 66 characters including '0x', got ${clean.length}`);
    }
    return clean;
  }

  /**
   * Calls `issueDocument` on the Sepolia smart contract.
   * @param documentHash bytes32 document hash
   * @param citizenAddress Checksummed citizen wallet address
   * @param docType Type/category of the document
   */
  async issueDocument(
    documentHash: string,
    citizenAddress: string,
    docType: string
  ): Promise<ethers.ContractTransactionReceipt> {
    const formattedHash = RelayerService.formatBytes32(documentHash);
    const checksummedCitizen = ethers.getAddress(citizenAddress);

    const tx = await this.contract.issueDocument(formattedHash, checksummedCitizen, docType);
    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error('Transaction was submitted but failed to obtain receipt');
    }
    return receipt;
  }

  /**
   * Calls `revokeDocument` on the Sepolia smart contract.
   * @param documentHash bytes32 document hash
   */
  async revokeDocument(documentHash: string): Promise<ethers.ContractTransactionReceipt> {
    const formattedHash = RelayerService.formatBytes32(documentHash);
    const tx = await this.contract.revokeDocument(formattedHash);
    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error('Revoke transaction was submitted but failed to obtain receipt');
    }
    return receipt;
  }

  /**
   * Checks if an address has the ISSUER_ROLE on-chain.
   */
  async isIssuer(address: string): Promise<boolean> {
    try {
      const checksummed = ethers.getAddress(address);
      return await this.contract.isIssuer(checksummed);
    } catch (error) {
      console.error(`isIssuer check failed for ${address}:`, error);
      return false;
    }
  }

  /**
   * Queries all document hashes assigned to a citizen (0 gas view call).
   */
  async getCitizenDocuments(citizenAddress: string): Promise<string[]> {
    const checksummed = ethers.getAddress(citizenAddress);
    return await this.contract.getCitizenDocuments(checksummed);
  }

  /**
   * Retrieves on-chain metadata for a document hash.
   */
  async getDocument(documentHash: string): Promise<any> {
    const formattedHash = RelayerService.formatBytes32(documentHash);
    return await this.contract.documents(formattedHash);
  }

  /**
   * Returns current relayer wallet address.
   */
  getRelayerAddress(): string {
    return this.wallet.address;
  }
}
