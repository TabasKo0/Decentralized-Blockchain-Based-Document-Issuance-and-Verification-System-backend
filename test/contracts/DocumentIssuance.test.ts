import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

describe("DocumentIssuanceConsortium", function () {
  let documentIssuance: any;
  let admin: any;
  let issuer1: any;
  let issuer2: any;
  let citizen1: any;
  let citizen2: any;
  let unauthorized: any;
  let ISSUER_ROLE: string;
  let DEFAULT_ADMIN_ROLE: string;

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    admin = signers[0];
    issuer1 = signers[1];
    issuer2 = signers[2];
    citizen1 = signers[3];
    citizen2 = signers[4];
    unauthorized = signers[5];

    const DocumentIssuance = await ethers.getContractFactory("DocumentIssuanceConsortium");
    documentIssuance = await DocumentIssuance.deploy();

    ISSUER_ROLE = await documentIssuance.ISSUER_ROLE();
    DEFAULT_ADMIN_ROLE = await documentIssuance.DEFAULT_ADMIN_ROLE();
  });

  describe("Deployment & RBAC", function () {
    it("Should set the right admin", async function () {
      expect(await documentIssuance.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.equal(true);
    });

    it("Should allow admin to grant ISSUER_ROLE", async function () {
      await expect(documentIssuance.grantRole(ISSUER_ROLE, issuer1.address))
        .to.emit(documentIssuance, "RoleGranted")
        .withArgs(ISSUER_ROLE, issuer1.address, admin.address);
        
      expect(await documentIssuance.hasRole(ISSUER_ROLE, issuer1.address)).to.equal(true);
    });

    it("Should not allow unauthorized to grant ISSUER_ROLE", async function () {
      await expect(documentIssuance.connect(unauthorized).grantRole(ISSUER_ROLE, issuer1.address))
        .to.be.revertedWithCustomError(documentIssuance, "AccessControlUnauthorizedAccount")
        .withArgs(unauthorized.address, DEFAULT_ADMIN_ROLE);
    });
  });

  describe("Issuance", function () {
    beforeEach(async function () {
      await documentIssuance.grantRole(ISSUER_ROLE, issuer1.address);
    });

    it("Should allow issuer to issue an official document", async function () {
      const docHash = ethers.id("official_doc_1");
      const docType = "Degree";

      await expect(documentIssuance.connect(issuer1).issueDocument(docHash, citizen1.address, docType))
        .to.emit(documentIssuance, "DocumentIssued")
        .withArgs(docHash, issuer1.address, citizen1.address);

      const record = await documentIssuance.documents(docHash);
      expect(record.documentHash).to.equal(docHash);
      expect(record.issuer).to.equal(issuer1.address);
      expect(record.citizen).to.equal(citizen1.address);
      expect(record.docType).to.equal(docType);
      expect(record.isRevoked).to.equal(false);
      expect(record.issuedAt).to.be.greaterThan(0);
    });

    it("Should prevent non-issuer from issuing an official document", async function () {
      const docHash = ethers.id("official_doc_2");

      await expect(documentIssuance.connect(unauthorized).issueDocument(docHash, citizen1.address, "Degree"))
        .to.be.revertedWithCustomError(documentIssuance, "AccessControlUnauthorizedAccount")
        .withArgs(unauthorized.address, ISSUER_ROLE);
    });

    it("Should prevent duplicate document hashes during official issuance", async function () {
      const docHash = ethers.id("official_doc_3");

      await documentIssuance.connect(issuer1).issueDocument(docHash, citizen1.address, "Degree");

      await expect(documentIssuance.connect(issuer1).issueDocument(docHash, citizen1.address, "Degree"))
        .to.be.revertedWith("Document hash already exists");
    });
  });



  describe("Revocation", function () {
    let docHash: string;

    beforeEach(async function () {
      await documentIssuance.grantRole(ISSUER_ROLE, issuer1.address);
      docHash = ethers.id("doc_to_revoke");
      await documentIssuance.connect(issuer1).issueDocument(docHash, citizen1.address, "Degree");
    });

    it("Should allow the original issuer to revoke a document", async function () {
      await expect(documentIssuance.connect(issuer1).revokeDocument(docHash))
        .to.emit(documentIssuance, "DocumentRevoked")
        .withArgs(docHash, issuer1.address);

      const record = await documentIssuance.documents(docHash);
      expect(record.isRevoked).to.equal(true);
    });

    it("Should prevent revocation by a non-issuer of the document", async function () {
      await expect(documentIssuance.connect(issuer2).revokeDocument(docHash))
        .to.be.revertedWith("Only the issuer can revoke");

      await expect(documentIssuance.connect(unauthorized).revokeDocument(docHash))
        .to.be.revertedWith("Only the issuer can revoke");
    });

    it("Should prevent revocation of a non-existent document", async function () {
      const invalidHash = ethers.id("invalid");

      await expect(documentIssuance.connect(issuer1).revokeDocument(invalidHash))
        .to.be.revertedWith("Document does not exist");
    });

    it("Should prevent double revocation", async function () {
      await documentIssuance.connect(issuer1).revokeDocument(docHash);

      await expect(documentIssuance.connect(issuer1).revokeDocument(docHash))
        .to.be.revertedWith("Document is already revoked");
    });
  });

  describe("View Functions", function () {
    it("Should retrieve all document hashes for a citizen", async function () {
      await documentIssuance.grantRole(ISSUER_ROLE, issuer1.address);

      const hash1 = ethers.id("doc1");
      const hash2 = ethers.id("doc2");
      const hash3 = ethers.id("doc3");

      await documentIssuance.connect(issuer1).issueDocument(hash1, citizen1.address, "Degree");
      await documentIssuance.connect(issuer1).issueDocument(hash2, citizen1.address, "ID");
      await documentIssuance.connect(issuer1).issueDocument(hash3, citizen1.address, "Certificate");

      const citizenDocs = await documentIssuance.getCitizenDocuments(citizen1.address);
      
      expect(citizenDocs).to.have.lengthOf(3);
      expect(citizenDocs[0]).to.equal(hash1);
      expect(citizenDocs[1]).to.equal(hash2);
      expect(citizenDocs[2]).to.equal(hash3);
    });
  });
});
