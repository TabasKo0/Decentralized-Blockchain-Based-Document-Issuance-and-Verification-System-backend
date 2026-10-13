import 'dotenv/config';
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
    contractAddress: string = process.env.CONTRACT_ADDRESS || '0xa08Bfaf6f138c91e9a9562240030E6AdF7F3cF5e',
    injectedSigner?: ethers.Signer
  ) {
    const isSepolia = rpcUrl.includes('sepolia');
    if (injectedSigner) {
      this.provider = injectedSigner.provider as ethers.JsonRpcProvider;
      this.wallet = injectedSigner as any;
    } else {
      const formattedKey = RelayerService.formatPrivateKey(privateKey);
      this.provider = isSepolia
        ? new ethers.JsonRpcProvider(rpcUrl, 11155111, { staticNetwork: true })
        : new ethers.JsonRpcProvider(rpcUrl);
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
  public static formatBytes32(hash: string): string {
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
   * Calls `issueDocument` on the Sepolia smart contract v2.
   * @param documentHash bytes32 document hash
   * @param citizenAddress Checksummed citizen wallet address
   * @param docType Type/category of the document
   * @param expiresAt Unix epoch timestamp in seconds (0 for non-expiring)
   */
  async issueDocument(
    documentHash: string,
    citizenAddress: string,
    docType: string,
    expiresAt: number = 0
  ): Promise<ethers.ContractTransactionReceipt> {
    const formattedHash = RelayerService.formatBytes32(documentHash);
    const checksummedCitizen = ethers.getAddress(citizenAddress);

    let tx;
    if (expiresAt > 0) {
      tx = await this.contract['issueDocument(bytes32,address,string,uint64)'](
        formattedHash,
        checksummedCitizen,
        docType,
        BigInt(expiresAt)
      );
    } else {
      tx = await this.contract['issueDocument(bytes32,address,string)'](
        formattedHash,
        checksummedCitizen,
        docType
      );
    }

    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error('Transaction was submitted but failed to obtain receipt');
    }
    return receipt;
  }

  /**
   * Calls `revokeDocument` on the Sepolia smart contract v2 with an immutable reason.
   * @param documentHash bytes32 document hash
   * @param reason Human-readable revocation reason permanently anchored on-chain
   */
  async revokeDocument(
    documentHash: string,
    reason: string = 'REVOKED_BY_ISSUER'
  ): Promise<ethers.ContractTransactionReceipt> {
    const formattedHash = RelayerService.formatBytes32(documentHash);
    const tx = await this.contract['revokeDocument(bytes32,string)'](formattedHash, reason);
    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error('Revoke transaction was submitted but failed to obtain receipt');
    }
    return receipt;
  }

  /**
   * Supersedes an old document with a new document hash, establishing an on-chain provenance chain.
   */
  async supersedeDocument(
    oldHash: string,
    newHash: string
  ): Promise<ethers.ContractTransactionReceipt> {
    const formattedOld = RelayerService.formatBytes32(oldHash);
    const formattedNew = RelayerService.formatBytes32(newHash);

    const tx = await this.contract.supersedeDocument(formattedOld, formattedNew);
    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error('Supersede transaction was submitted but failed to obtain receipt');
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
