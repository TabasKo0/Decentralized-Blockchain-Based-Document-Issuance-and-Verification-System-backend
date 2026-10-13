// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract DocumentIssuanceConsortium is AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    address public admin;

    struct DocumentRecord {
        bytes32 documentHash;
        address issuer;
        address citizen;
        string docType;
        uint256 issuedAt;
        bool isRevoked;
        string revocationReason;
        bytes32 supersededBy;
        uint64 expiresAt; // 0 for non-expiring
    }

    mapping(bytes32 => DocumentRecord) public documents;
    mapping(address => bytes32[]) private citizenDocuments;

    event DocumentIssued(
        bytes32 indexed documentHash, 
        address indexed issuer, 
        address indexed citizen,
        uint64 expiresAt
    );
    event DocumentRevoked(
        bytes32 indexed documentHash, 
        address indexed issuer,
        string reason
    );
    event DocumentSuperseded(
        bytes32 indexed oldHash,
        bytes32 indexed newHash,
        address indexed issuer
    );
    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Error: Only the admin can perform this action");
        _;
    }

    modifier onlyIssuer() {
        require(hasRole(ISSUER_ROLE, msg.sender), "Error: Only an authorized issuer can perform this action");
        _;
    }

    constructor() {
        admin = msg.sender;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        emit AdminTransferred(address(0), msg.sender);
    }

    /**
     * @dev Check if an address has the ISSUER_ROLE.
     */
    function isIssuer(address _account) external view returns (bool) {
        return hasRole(ISSUER_ROLE, _account);
    }

    /**
     * @dev Gives an organization (e.g. University/Hospital) permission to issue official documents.
     */
    function addIssuer(address _newIssuer) external onlyAdmin {
        require(_newIssuer != address(0), "Cannot add zero address");
        require(!hasRole(ISSUER_ROLE, _newIssuer), "Already an issuer");

        _grantRole(ISSUER_ROLE, _newIssuer);
        emit IssuerAdded(_newIssuer);
    }

    /**
     * @dev Revokes an organization's permission to issue documents.
     */
    function removeIssuer(address _issuer) external onlyAdmin {
        require(hasRole(ISSUER_ROLE, _issuer), "Not currently an issuer");

        _revokeRole(ISSUER_ROLE, _issuer);
        emit IssuerRemoved(_issuer);
    }

    /**
     * @dev Allows the current admin to hand over the admin key to a new wallet.
     */
    function transferAdmin(address _newAdmin) external onlyAdmin {
        require(_newAdmin != address(0), "Cannot transfer to zero address");

        address oldAdmin = admin;
        admin = _newAdmin;

        _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
        _grantRole(DEFAULT_ADMIN_ROLE, _newAdmin);

        emit AdminTransferred(oldAdmin, _newAdmin);
    }

    function _issueDocumentInternal(
        bytes32 _documentHash, 
        address _citizen, 
        string calldata _docType,
        uint64 _expiresAt
    ) internal {
        require(documents[_documentHash].issuedAt == 0, "Document hash already exists");
        require(_citizen != address(0), "Cannot issue to zero address");

        documents[_documentHash] = DocumentRecord({
            documentHash: _documentHash,
            issuer: msg.sender,
            citizen: _citizen,
            docType: _docType,
            issuedAt: block.timestamp,
            isRevoked: false,
            revocationReason: "",
            supersededBy: bytes32(0),
            expiresAt: _expiresAt
        });

        citizenDocuments[_citizen].push(_documentHash);

        emit DocumentIssued(_documentHash, msg.sender, _citizen, _expiresAt);
    }

    /**
     * @dev Standard issuance (non-expiring, _expiresAt = 0).
     */
    function issueDocument(
        bytes32 _documentHash, 
        address _citizen, 
        string calldata _docType
    ) external onlyIssuer {
        _issueDocumentInternal(_documentHash, _citizen, _docType, 0);
    }

    /**
     * @dev Issuance with explicit expiration timestamp.
     */
    function issueDocument(
        bytes32 _documentHash, 
        address _citizen, 
        string calldata _docType,
        uint64 _expiresAt
    ) external onlyIssuer {
        _issueDocumentInternal(_documentHash, _citizen, _docType, _expiresAt);
    }

    /**
     * @dev Revokes a document with an immutable reason anchored on Sepolia.
     */
    function revokeDocument(bytes32 _documentHash, string memory _reason) public {
        DocumentRecord storage doc = documents[_documentHash];
        require(doc.issuedAt != 0, "Document does not exist");
        require(doc.issuer == msg.sender, "Only the issuer can revoke");
        require(!doc.isRevoked, "Document is already revoked");

        doc.isRevoked = true;
        doc.revocationReason = _reason;

        emit DocumentRevoked(_documentHash, msg.sender, _reason);
    }

    /**
     * @dev Overload for revocation without explicit reason (defaults to UNSPECIFIED).
     */
    function revokeDocument(bytes32 _documentHash) external {
        revokeDocument(_documentHash, "UNSPECIFIED");
    }

    /**
     * @dev Supersedes an old document with a newly issued document, forming a version chain.
     */
    function supersedeDocument(bytes32 _oldHash, bytes32 _newHash) external {
        DocumentRecord storage oldDoc = documents[_oldHash];
        require(oldDoc.issuedAt != 0, "Old document does not exist");
        require(oldDoc.issuer == msg.sender, "Only the issuer can supersede");
        require(!oldDoc.isRevoked, "Old document is already revoked");
        require(documents[_newHash].issuedAt != 0, "New document must exist before superseding");
        require(documents[_newHash].issuer == msg.sender, "New document must be from same issuer");

        oldDoc.isRevoked = true;
        oldDoc.revocationReason = "SUPERSEDED";
        oldDoc.supersededBy = _newHash;

        emit DocumentSuperseded(_oldHash, _newHash, msg.sender);
        emit DocumentRevoked(_oldHash, msg.sender, "SUPERSEDED");
    }

    /**
     * @dev Free read function (0 gas) to fetch all document hashes owned by a citizen.
     */
    function getCitizenDocuments(address _citizen) external view returns (bytes32[] memory) {
        return citizenDocuments[_citizen];
    }
}
