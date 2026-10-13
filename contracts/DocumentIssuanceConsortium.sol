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
    }

    mapping(bytes32 => DocumentRecord) public documents;
    mapping(address => bytes32[]) private citizenDocuments;

    event DocumentIssued(
        bytes32 indexed documentHash, 
        address indexed issuer, 
        address indexed citizen
    );
    event DocumentRevoked(
        bytes32 indexed documentHash, 
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
     * Can ONLY be called by the Admin.
     */
    function addIssuer(address _newIssuer) external onlyAdmin {
        require(_newIssuer != address(0), "Cannot add zero address");
        require(!hasRole(ISSUER_ROLE, _newIssuer), "Already an issuer");

        _grantRole(ISSUER_ROLE, _newIssuer);
        emit IssuerAdded(_newIssuer);
    }

    /**
     * @dev Revokes an organization's permission to issue documents.
     * Can ONLY be called by the Admin.
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

    /**
     * @dev Issues an official certificate or document.
     * Protected by `onlyIssuer` modifier.
     */
    function issueDocument(
        bytes32 _documentHash, 
        address _citizen, 
        string calldata _docType
    ) external onlyIssuer {
        require(documents[_documentHash].issuedAt == 0, "Document hash already exists");

        documents[_documentHash] = DocumentRecord({
            documentHash: _documentHash,
            issuer: msg.sender,
            citizen: _citizen,
            docType: _docType,
            issuedAt: block.timestamp,
            isRevoked: false
        });

        citizenDocuments[_citizen].push(_documentHash);

        emit DocumentIssued(_documentHash, msg.sender, _citizen);
    }

    /**
     * @dev Revokes a document. Only the original issuer can revoke it.
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
     * @dev Free read function (0 gas) to fetch all document hashes owned by a citizen.
     */
    function getCitizenDocuments(address _citizen) external view returns (bytes32[] memory) {
        return citizenDocuments[_citizen];
    }
}

