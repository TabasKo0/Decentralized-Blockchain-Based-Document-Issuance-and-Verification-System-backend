import pinataSDK from '@pinata/sdk';
import { Readable } from 'stream';

const pinataJwt = process.env.PINATA_JWT || '';
// Handle ESM/CJS interop for @pinata/sdk
const PinataClientConstructor = (pinataSDK as any).default || pinataSDK;
export const pinata = new (PinataClientConstructor as any)({ pinataJWTKey: pinataJwt });

export class PinataService {
  /**
   * Pins an arbitrary JSON payload (encrypted document payload, metadata, etc.) to IPFS.
   * @param payload JSON data to pin
   * @param name Optional pin name for Pinata explorer
   * @returns IPFS CID string
   */
  static async pinJSONToIPFS(payload: any, name?: string): Promise<string> {
    const options = name
      ? {
          pinataMetadata: {
            name,
          },
        }
      : undefined;

    try {
      if (typeof pinata?.pinJSONToIPFS === 'function') {
        const result = await pinata.pinJSONToIPFS(payload, options);
        if (result?.IpfsHash) {
          return result.IpfsHash;
        }
      }

      // Fallback via REST API if PINATA_JWT is present
      if (process.env.PINATA_JWT) {
        const response = await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${process.env.PINATA_JWT}`,
          },
          body: JSON.stringify({
            pinataContent: payload,
            pinataMetadata: options?.pinataMetadata,
          }),
        });

        if (!response.ok) {
          const errText = await response.text();
          throw new Error(`Pinata API returned ${response.status}: ${errText}`);
        }

        const data = (await response.json()) as { IpfsHash: string };
        return data.IpfsHash;
      }

      throw new Error('Pinata credentials not configured or pinning failed');
    } catch (error: any) {
      console.error('Pinata pinJSONToIPFS error:', error);
      throw new Error(`Failed to pin JSON payload to IPFS: ${error.message}`);
    }
  }

  /**
   * Pins a raw file buffer directly to IPFS.
   * @param buffer Raw buffer to upload
   * @param filename Filename metadata
   * @returns IPFS CID string
   */
  static async pinBufferToIPFS(buffer: Buffer, filename: string = 'encrypted_document.enc'): Promise<string> {
    try {
      const stream = Readable.from(buffer);
      (stream as any).path = filename;

      const result = await pinata.pinFileToIPFS(stream, {
        pinataMetadata: {
          name: filename,
        },
      });

      return result.IpfsHash;
    } catch (error: any) {
      console.error('Pinata pinBufferToIPFS error:', error);
      throw new Error(`Failed to pin buffer to IPFS: ${error.message}`);
    }
  }

  /**
   * Fetches an IPFS payload from gateway.
   * @param cid IPFS Content Identifier
   */
  static async fetchFromIPFS(cid: string): Promise<any> {
    const gateway = process.env.PINATA_GATEWAY || 'https://gateway.pinata.cloud/ipfs';
    const response = await fetch(`${gateway}/${cid}`);
    if (!response.ok) {
      throw new Error(`IPFS gateway returned status: ${response.status}`);
    }
    return await response.json();
  }
}
