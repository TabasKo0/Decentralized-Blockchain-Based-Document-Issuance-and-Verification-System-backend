import 'dotenv/config';
import pinataSDK from '@pinata/sdk';
import { Readable } from 'stream';

const PinataClientConstructor = (pinataSDK as any).default || pinataSDK;

/**
 * Creates and returns an initialized Pinata SDK client based on available environment variables.
 * Supports either PINATA_JWT or PINATA_API_KEY + PINATA_SECRET_API_KEY.
 */
export function createPinataClient() {
  const jwt = process.env.PINATA_JWT?.trim();
  const apiKey = process.env.PINATA_API_KEY?.trim();
  const apiSecret = (process.env.PINATA_SECRET_API_KEY || process.env.PINATA_API_SECRET)?.trim();

  if (jwt) {
    return new (PinataClientConstructor as any)({ pinataJWTKey: jwt });
  }

  if (apiKey && apiSecret) {
    return new (PinataClientConstructor as any)(apiKey, apiSecret);
  }

  // Fallback dummy credentials to prevent crashing on import if unconfigured
  return new (PinataClientConstructor as any)('dummy_key', 'dummy_secret');
}

// Global mutable mock store for testing overrides
const mockOverrides: Record<string, any> = {};

// Transparent proxy to support dynamic initialization and unit-test mocking
export const pinata: any = new Proxy({}, {
  get(target, prop: string) {
    if (prop in mockOverrides) {
      return mockOverrides[prop];
    }
    const client = createPinataClient();
    const value = client[prop];
    return typeof value === 'function' ? value.bind(client) : value;
  },
  set(target, prop: string, value: any) {
    mockOverrides[prop] = value;
    return true;
  },
  deleteProperty(target, prop: string) {
    delete mockOverrides[prop];
    return true;
  },
});

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

      // Fallback via direct Pinata REST API
      const jwt = process.env.PINATA_JWT?.trim();
      const apiKey = process.env.PINATA_API_KEY?.trim();
      const apiSecret = (process.env.PINATA_SECRET_API_KEY || process.env.PINATA_API_SECRET)?.trim();

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (jwt) {
        headers['Authorization'] = `Bearer ${jwt}`;
      } else if (apiKey && apiSecret) {
        headers['pinata_api_key'] = apiKey;
        headers['pinata_secret_api_key'] = apiSecret;
      } else {
        throw new Error('No Pinata credentials provided. Please set PINATA_JWT or PINATA_API_KEY and PINATA_SECRET_API_KEY in .env');
      }

      const response = await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
        method: 'POST',
        headers,
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
