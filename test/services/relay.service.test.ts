import { expect } from 'chai';
import { network } from 'hardhat';
import { RelayService } from '../../src/services/relay.service';

describe('RelayService', function () {
  let ethers: any;
  let relayService: RelayService;
  let contractAddress: string;
  let citizenAddress: string;
  let issuerAddress: string;
  let docHash: string;

  before(async function () {
    const deps = await network.create();
    ethers = deps.ethers;
    
    const signers = await ethers.getSigners();
    // Admin/Funder is signers[0]
    const funder = signers[0];
    const issuer = signers[1];
    const citizen = signers[2];

    issuerAddress = issuer.address;
    citizenAddress = citizen.address;

    const DocumentIssuance = await ethers.getContractFactory("DocumentIssuanceConsortium");
    const documentIssuance = await DocumentIssuance.deploy();
    contractAddress = await documentIssuance.getAddress();

    // Grant ISSUER_ROLE to funder so the relayer can issue documents
    const ISSUER_ROLE = await documentIssuance.ISSUER_ROLE();
    await documentIssuance.grantRole(ISSUER_ROLE, funder.address);

    // Initialize RelayService with injected signer
    relayService = new RelayService(
      'dummy-rpc', 
      'dummy-key', 
      contractAddress, 
      funder // Injected signer
    );
  });

  it('should issue a document on-chain', async function () {
    docHash = ethers.id("relay_doc_1");
    
    await relayService.issueDocumentOnChain(docHash, citizenAddress, "Degree");
    
    const docs = await relayService.getCitizenDocuments(citizenAddress);
    expect(docs).to.include(docHash);
  });

  it('should upload a personal document on-chain', async function () {
    const personalHash = ethers.id("relay_personal_doc_1");
    
    await relayService.uploadPersonalDocumentOnChain(personalHash, "ID");
    
    // The relayer is signers[0], so it should be in signers[0] citizen docs
    const funderAddress = (await ethers.getSigners())[0].address;
    const docs = await relayService.getCitizenDocuments(funderAddress);
    expect(docs).to.include(personalHash);
  });

  it('should revoke a document on-chain', async function () {
    await relayService.revokeDocumentOnChain(docHash);
    
    try {
      await relayService.revokeDocumentOnChain(docHash);
      expect.fail("Should have thrown an error on double revocation");
    } catch (e: any) {
      expect(e.message).to.include("Document is already revoked");
    }
  });
});
