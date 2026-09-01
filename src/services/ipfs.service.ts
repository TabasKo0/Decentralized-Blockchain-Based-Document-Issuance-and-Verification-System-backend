import pinataSDK from '@pinata/sdk';

const pinataApiKey = process.env.PINATA_API_KEY || 'dummy-key';
const pinataApiSecret = process.env.PINATA_API_SECRET || 'dummy-secret';

// Initialize Pinata SDK
export const pinata = new pinataSDK(pinataApiKey, pinataApiSecret);

export class IpfsService {
  /**
   * Uploads a JSON payload (containing encrypted document, IV, session key, etc.) to IPFS via Pinata.
   * @param payload JSON object representing the document payload.
   * @returns IPFS CID string.
   */
  static async uploadPayload(payload: any): Promise<string> {
    try {
      const result = await pinata.pinJSONToIPFS(payload);
      return result.IpfsHash;
    } catch (error) {
      console.error('Error uploading to IPFS:', error);
      throw new Error('Failed to upload payload to IPFS');
    }
  }

  /**
   * Fetches an encrypted payload from IPFS via a public gateway.
   * @param cid The IPFS Content Identifier.
   * @returns The JSON payload.
   */
  static async fetchPayload(cid: string): Promise<any> {
    const gateway = process.env.IPFS_GATEWAY || 'https://gateway.pinata.cloud/ipfs';
    try {
      const response = await fetch(`${gateway}/${cid}`);
      if (!response.ok) {
        throw new Error(`IPFS gateway returned status: ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error('Error fetching from IPFS:', error);
      throw new Error('Failed to fetch payload from IPFS');
    }
  }
}
