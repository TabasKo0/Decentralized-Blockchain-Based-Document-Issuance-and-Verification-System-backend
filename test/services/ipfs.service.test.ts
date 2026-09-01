import { expect } from 'chai';
import { IpfsService, pinata } from '../../src/services/ipfs.service';

describe('IpfsService', function () {
  it('should have uploadPayload method', function () {
    expect(IpfsService.uploadPayload).to.be.a('function');
  });

  it('should have fetchPayload method', function () {
    expect(IpfsService.fetchPayload).to.be.a('function');
  });

  it('should upload a payload and return a dummy CID', async function () {
    const dummyCid = 'QmDummyUploadCid123';
    
    // Manual mock
    const originalPin = pinata.pinJSONToIPFS;
    let calledPayload: any;
    pinata.pinJSONToIPFS = async (payload: any, options?: any) => {
      calledPayload = payload;
      return { IpfsHash: dummyCid } as any;
    };
    
    try {
      const payload = { data: 'test' };
      const cid = await IpfsService.uploadPayload(payload);
      
      expect(cid).to.equal(dummyCid);
      expect(calledPayload).to.deep.equal(payload);
    } finally {
      // Restore
      pinata.pinJSONToIPFS = originalPin;
    }
  });

  it('should fetch payload using global fetch', async function () {
    const dummyCid = 'QmDummyCid';
    const dummyResponse = { data: 'encrypted_data' };
    
    // Mock global fetch
    const originalFetch = global.fetch;
    global.fetch = (async (url: RequestInfo | URL, options?: RequestInit) => {
      expect(url.toString()).to.include(dummyCid);
      return {
        ok: true,
        json: async () => dummyResponse
      } as Response;
    }) as unknown as typeof fetch;

    try {
      const result = await IpfsService.fetchPayload(dummyCid);
      expect(result).to.deep.equal(dummyResponse);
    } finally {
      global.fetch = originalFetch; // Restore
    }
  });
});
