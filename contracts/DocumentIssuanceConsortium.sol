// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract DocumentIssuanceConsortium is AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    struct DocumentRecord {
        bytes32 documentHash;
        address issuer;
        address citizen;
        string docType;
        uint256 issuedAt;
        bool isOfficial;
        bool isRevoked;
    }

    mapping(bytes32 => DocumentRecord) public documents;
    mapping(address => bytes32[]) private citizenDocuments;

    event DocumentIssued(bytes32 indexed documentHash, address indexed issuer, address indexed citizen, bool isOfficial);
    event DocumentRevoked(bytes32 indexed documentHash, address indexed issuer);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @dev Issues an official document. Only accounts with ISSUER_ROLE can call this.
     * @param _documentHash The unique hash of the encrypted document.
     * @param _citizen The wallet address of the citizen receiving the document.
     * @param _docType A string indicating the document type (e.g., "Degree", "ID").
     */
    function issueDocument(bytes32 _documentHash, address _citizen, string calldata _docType) external onlyRole(ISSUER_ROLE) {
        require(documents[_documentHash].issuedAt == 0, "Document hash already exists");

        documents[_documentHash] = DocumentRecord({
            documentHash: _documentHash,
            issuer: msg.sender,
            citizen: _citizen,
            docType: _docType,
            issuedAt: block.timestamp,
            isOfficial: true,
            isRevoked: false
        });

        citizenDocuments[_citizen].push(_documentHash);

        emit DocumentIssued(_documentHash, msg.sender, _citizen, true);
    }

    /**
     * @dev Uploads a personal, unofficial document by any citizen.
     * @param _documentHash The unique hash of the encrypted document.
     * @param _docType A string indicating the document type.
     */
    function uploadPersonalDocument(bytes32 _documentHash, string calldata _docType) external {
        require(documents[_documentHash].issuedAt == 0, "Document hash already exists");

        documents[_documentHash] = DocumentRecord({
            documentHash: _documentHash,
            issuer: msg.sender,
            citizen: msg.sender,
            docType: _docType,
            issuedAt: block.timestamp,
            isOfficial: false,
            isRevoked: false
        });

        citizenDocuments[msg.sender].push(_documentHash);

        emit DocumentIssued(_documentHash, msg.sender, msg.sender, false);
    }

    /**
     * @dev Revokes an existing document. Only the original issuer can revoke it.
     * @param _documentHash The unique hash of the document to revoke.
     */
    function revokeDocument(bytes32 _documentHash) external {
        DocumentRecord storage doc = documents[_documentHash];
        require(doc.issuedAt != 0, "Document does not exist");
        require(doc.issuer == msg.sender, "Only the issuer can revoke");
        require(!doc.isRevoked, "Document is already revoked");

        doc.isRevoked = true;

        emit DocumentRevoked(_documentHash, msg.sender);
    }

    /**
     * @dev Retrieves all document hashes associated with a citizen's address.
     * @param _citizen The address of the citizen.
     * @return An array of bytes32 document hashes.
     */
    function getCitizenDocuments(address _citizen) external view returns (bytes32[] memory) {
        return citizenDocuments[_citizen];
    }
}
