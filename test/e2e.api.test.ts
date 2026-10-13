import { expect } from 'chai';
import request from 'supertest';
import { network } from 'hardhat';
import http from 'http';
import app from '../src/app';
import { prisma } from '../src/db';
import { pinata } from '../src/services/ipfs.service';

describe('Phase 6: End-to-End API Integration', function () {
  let contractAddress: string;
  let citizenToken: string;
  let issuerToken: string;
  let citizenWalletAddress: string;
  let citizenShareC: string;
  let documentHash: string;
  
  let originalPin: any;
  
  let mockDb: Record<string, any> = {};
  let rpcServer: http.Server;
  let originalFindUnique: any;
  let originalCreate: any;
  let ethers: any;

  before(async function () {
    ({ ethers } = await network.create());

    // 0. Start an HTTP JSON-RPC proxy to bridge Express to the in-memory Hardhat network
    rpcServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => body += chunk.toString());
      req.on('end', async () => {
        try {
          const payload = JSON.parse(body);
          if (Array.isArray(payload)) {
            const responses = await Promise.all(payload.map(async (p) => {
              const result = await ethers.provider.send(p.method, p.params || []);
              return { jsonrpc: '2.0', id: p.id, result };
            }));
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(responses));
          } else {
            const result = await ethers.provider.send(payload.method, payload.params || []);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', id: payload.id, result }));
          }
        } catch (err: any) {
          res.writeHead(500);
          res.end(err.message);
        }
      });
    });
    await new Promise<void>(resolve => rpcServer.listen(0, resolve));
    const port = (rpcServer.address() as any).port;

    // 1. Setup Hardhat local network and deploy contract
    const signers = await ethers.getSigners();
    const admin = signers[0];
    
    const ContractFactory = await ethers.getContractFactory('contracts/DocumentIssuanceConsortium.sol:DocumentIssuanceConsortium', admin);
    const contract = await ContractFactory.deploy();
    await contract.waitForDeployment();
    
    // Grant ISSUER_ROLE to the Relayer account
    await contract.addIssuer(admin.address);
    
    contractAddress = await contract.getAddress();
    
    // Inject dynamic environment variables
    process.env.CONTRACT_ADDRESS = contractAddress;
    process.env.RPC_URL = `http://127.0.0.1:${port}`;
    
    // 2. Mock Pinata IPFS to avoid network dependencies
    originalPin = pinata.pinJSONToIPFS;
    pinata.pinJSONToIPFS = async (payload: any, options?: any) => {
      return { IpfsHash: 'QmDummyE2eCid123' } as any;
    };
    
    // 3. Mock Prisma to avoid needing a real Postgres instance
    originalFindUnique = prisma.user.findUnique;
    originalCreate = prisma.user.create;

    prisma.user.findUnique = async (args: any) => {
      if (args.where.email) return mockDb[args.where.email] || null;
      if (args.where.walletAddress) {
        return Object.values(mockDb).find((u: any) => u.walletAddress === args.where.walletAddress) || null;
      }
      return null;
    };
    prisma.user.create = async (args: any) => {
      const user = { ...args.data, id: `mock-id-${Date.now()}` };
      mockDb[user.email] = user;
      return user as any;
    };
    
    // Clear mock DB
    mockDb = {};
  });

  after(async function () {
    // Restore mocks
    pinata.pinJSONToIPFS = originalPin;
    prisma.user.findUnique = originalFindUnique;
    prisma.user.create = originalCreate;
    
    rpcServer.close();
  });

  it('Step 1: Register Citizen', async function () {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'citizen@e2e.com', password: 'secure_password', isIssuer: false });

    expect(res.status).to.equal(200);
    expect(res.body.success).to.be.true;
    expect(res.body.token).to.exist;
    expect(res.body.shareA).to.exist;
    expect(res.body.shareC).to.exist;
    expect(res.body.user.walletAddress).to.exist;

    citizenToken = res.body.token;
    citizenShareC = res.body.shareC;
    citizenWalletAddress = res.body.user.walletAddress;
  });

  it('Step 2: Register & Authorize Issuer', async function () {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'issuer@e2e.com', password: 'secure_password', isIssuer: true });

    expect(res.status).to.equal(200);
    expect(res.body.success).to.be.true;
    expect(res.body.token).to.exist;
    
    issuerToken = res.body.token;
    const issuerWallet = res.body.user.walletAddress;

    // The backend registered them, but on the blockchain, the Admin must grant ISSUER_ROLE
    const signers = await ethers.getSigners();
    const admin = signers[0];
    const contract = await ethers.getContractAt('contracts/DocumentIssuanceConsortium.sol:DocumentIssuanceConsortium', contractAddress, admin);
    
    const tx = await contract.addIssuer(issuerWallet);
    await tx.wait();
  });

  it('Step 3: Issuer issues encrypted degree', async function () {
    // We send a multipart/form-data request to simulate a file upload
    const res = await request(app)
      .post('/api/documents/issue')
      .set('Authorization', `Bearer ${issuerToken}`)
      .field('citizenWalletAddress', citizenWalletAddress)
      .field('docType', 'Bachelor of Science')
      .attach('file', Buffer.from('Fake PDF content here'), 'degree.pdf');

    expect(res.status).to.equal(200);
    expect(res.body.success).to.be.true;
    expect(res.body.ipfsCID).to.equal('QmDummyE2eCid123');
    expect(res.body.documentHash).to.exist;
    expect(res.body.txHash).to.exist;

    documentHash = res.body.documentHash;
  });

  it('Step 4: Citizen fetches documents', async function () {
    const res = await request(app)
      .get('/api/documents/my-documents')
      .set('Authorization', `Bearer ${citizenToken}`);

    if (res.status !== 200) console.error('Step 4 Error:', res.body);
    expect(res.status).to.equal(200);
    expect(res.body.success).to.be.true;
    expect(res.body.documentHashes).to.be.an('array').that.includes(documentHash);
  });

  it('Step 5: Simulate device loss and recover key', async function () {
    const res = await request(app)
      .post('/api/auth/recover-key')
      .send({ email: 'citizen@e2e.com', shareC: citizenShareC });

    expect(res.status).to.equal(200);
    expect(res.body.success).to.be.true;
    expect(res.body.reconstructedPrivateKey).to.exist;
  });

  it('Step 6: Public verification check of document hash', async function () {
    const res = await request(app)
      .get(`/api/verify/${documentHash}`);

    if (res.status !== 200) console.error('Step 6 Error:', res.body);
    expect(res.status).to.equal(200);
    expect(res.body.success).to.be.true;
    expect(res.body.exists).to.be.true;
    expect(res.body.docType).to.equal('Bachelor of Science');
  });
});
