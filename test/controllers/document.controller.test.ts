import { expect } from 'chai';
import type { Response } from 'express';
import type { AuthRequest } from '../../src/middlewares/auth.middleware';
import { issue } from '../../src/controllers/document.controller';

const createMockResponse = () => {
  const res: any = {};
  res.statusCode = 200;
  res.data = null;
  res.status = function (code: number) { this.statusCode = code; return this; };
  res.json = function (data: any) { this.data = data; return this; };
  return res as Response;
};

describe('DocumentController Validation Tests', function () {
  it('issue should require file, citizenWalletAddress, and docType', async function () {
    const req = { 
      body: { citizenWalletAddress: '0x123' }
      // missing docType and file
    } as AuthRequest; 
    
    const res = createMockResponse();

    await issue(req, res);
    
    expect((res as any).statusCode).to.equal(400);
    expect((res as any).data.message).to.equal('Missing parameters');
  });
  
  it('issue should fail if citizenWalletAddress is missing', async function () {
    const req = { 
      body: { docType: 'Degree' },
      file: { buffer: Buffer.from('test') } as any
    } as AuthRequest; 
    
    const res = createMockResponse();

    await issue(req, res);
    
    expect((res as any).statusCode).to.equal(400);
    expect((res as any).data.message).to.equal('Missing parameters');
  });
});
