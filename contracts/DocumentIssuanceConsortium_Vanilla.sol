// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ==============================================================================
// 🎓 100% PURE SOLIDITY - NO OPENZEPPELIN / ZERO EXTERNAL DEPENDENCIES
// ==============================================================================
// In the previous version, we imported OpenZeppelin's "AccessControl" library.
// While OpenZeppelin is great for production, it hides a lot of magic "under the hood".
//
// In this file, we build EVERYTHING from raw, basic Solidity:
// - We create our own Admin variable.
// - We create our own Issuer permission mapping.
// - We write our own custom "modifiers" (security bouncers) from scratch!
// ==============================================================================

contract DocumentIssuanceConsortiumVanilla {

    // --------------------------------------------------------------------------
    // 1. STATE VARIABLES (Contract Memory stored permanently on Blockchain)
    // --------------------------------------------------------------------------

    // The Master Admin (the wallet that deployed this contract).
    // Analogy: The "Superuser" or "Root" account of the system.
    address public admin;

    // A mapping to track who is authorized to issue official documents.
    // Analogy: A VIP guest list or badge checker.
    // Key: Wallet Address (e.g. 0x123...)
    // Value: true (has badge) or false (no badge)
    mapping(address => bool) public isIssuer;

    // The ID card template for each document
    struct DocumentRecord {
        bytes32 documentHash; // Unique cryptographic fingerprint of the document
        address issuer;       // Who issued it (University/Hospital or Citizen)
        address citizen;      // Who received / owns it
        string docType;       // e.g. "Bachelor Degree", "National ID"
        uint256 issuedAt;     // Timestamp when recorded
        bool isOfficial;      // true if issued by an approved issuer, false if personal
        bool isRevoked;       // true if cancelled
    }

    // Lookup table: Document Hash -> Full Document Data
    mapping(bytes32 => DocumentRecord) public documents;

    // Lookup table: Citizen Address -> List of their Document Hashes
    mapping(address => bytes32[]) private citizenDocuments;


    // --------------------------------------------------------------------------
    // 2. EVENTS (Megaphones shouting to Web apps & Backend APIs)
    // --------------------------------------------------------------------------
    event DocumentIssued(
        bytes32 indexed documentHash, 
        address indexed issuer, 
        address indexed citizen, 
        bool isOfficial
    );
    
    event DocumentRevoked(
        bytes32 indexed documentHash, 
        address indexed issuer
    );

    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);


    // --------------------------------------------------------------------------
    // 3. CUSTOM MODIFIERS (Our Hand-Made Security Bouncers)
    // --------------------------------------------------------------------------
    // What is a "modifier"?
    // In Solidity, a modifier is a reusable piece of code that wraps around a function.
    // Think of it as a security checkpoint or middleware.
    //
    // The magical symbol `_;` is called the "MERGE POINT":
    // It tells Solidity: "First run the checks above. If they pass, now execute the actual function code here!"

    modifier onlyAdmin() {
        // Only the master admin can pass this check!
        require(msg.sender == admin, "Error: Only the admin can perform this action");
        _; // <-- Continue and run the rest of the function
    }

    modifier onlyIssuer() {
        // Only wallets that have the issuer badge (`isIssuer == true`) can pass!
        require(isIssuer[msg.sender], "Error: Only an authorized issuer can perform this action");
        _; // <-- Continue and run the rest of the function
    }


    // --------------------------------------------------------------------------
    // 4. CONSTRUCTOR (Runs once when the contract is deployed)
    // --------------------------------------------------------------------------
    constructor() {
        // The person deploying the contract becomes the first Master Admin!
        admin = msg.sender;
        emit AdminTransferred(address(0), msg.sender);
    }


    // --------------------------------------------------------------------------
    // 5. ROLE MANAGEMENT FUNCTIONS (Pure Vanilla Admin Controls)
    // --------------------------------------------------------------------------
    
    /**
     * @dev Gives an organization (e.g. University/Hospital) permission to issue official documents.
     * Can ONLY be called by the Admin.
     */
    function addIssuer(address _newIssuer) external onlyAdmin {
        require(_newIssuer != address(0), "Cannot add zero address");
        require(!isIssuer[_newIssuer], "Already an issuer");

        // Flip their badge to true
        isIssuer[_newIssuer] = true;

        emit IssuerAdded(_newIssuer);
    }

    /**
     * @dev Revokes an organization's permission to issue documents.
     * Can ONLY be called by the Admin.
     */
    function removeIssuer(address _issuer) external onlyAdmin {
        require(isIssuer[_issuer], "Not currently an issuer");

        // Flip their badge to false
        isIssuer[_issuer] = false;

        emit IssuerRemoved(_issuer);
    }

    /**
     * @dev Allows the current admin to hand over the admin key to a new wallet.
     */
    function transferAdmin(address _newAdmin) external onlyAdmin {
        require(_newAdmin != address(0), "Cannot transfer to zero address");
        
        address oldAdmin = admin;
        admin = _newAdmin;

        emit AdminTransferred(oldAdmin, _newAdmin);
    }


    // --------------------------------------------------------------------------
    // 6. CORE DOCUMENT LOGIC
    // --------------------------------------------------------------------------

    /**
     * @dev Issues an official certificate or document.
     * Protected by our custom `onlyIssuer` modifier!
     */
    function issueDocument(
        bytes32 _documentHash, 
        address _citizen, 
        string calldata _docType
    ) external onlyIssuer {
        // Ensure no duplicate hash
        require(documents[_documentHash].issuedAt == 0, "Document hash already exists");

        // Save to blockchain storage
        documents[_documentHash] = DocumentRecord({
            documentHash: _documentHash,
            issuer: msg.sender,
            citizen: _citizen,
            docType: _docType,
            issuedAt: block.timestamp,
            isOfficial: true,
            isRevoked: false
        });

        // Add hash to the citizen's portfolio
        citizenDocuments[_citizen].push(_documentHash);

        // Broadcast to listeners
        emit DocumentIssued(_documentHash, msg.sender, _citizen, true);
    }

    /**
     * @dev Allows any everyday citizen to upload their own personal document.
     * Anyone can call this function (no modifier restriction).
     */
    function uploadPersonalDocument(
        bytes32 _documentHash, 
        string calldata _docType
    ) external {
        // Ensure no duplicate hash
        require(documents[_documentHash].issuedAt == 0, "Document hash already exists");

        // Citizen is both the issuer and the recipient
        documents[_documentHash] = DocumentRecord({
            documentHash: _documentHash,
            issuer: msg.sender,
            citizen: msg.sender,
            docType: _docType,
            issuedAt: block.timestamp,
            isOfficial: false, // Explicitly marked as personal/unofficial!
            isRevoked: false
        });

        citizenDocuments[msg.sender].push(_documentHash);

        emit DocumentIssued(_documentHash, msg.sender, msg.sender, false);
    }

    /**
     * @dev Revokes a document. Only the original issuer can revoke it.
     */
    function revokeDocument(bytes32 _documentHash) external {
        // Pointer directly to permanent storage
        DocumentRecord storage doc = documents[_documentHash];

        require(doc.issuedAt != 0, "Document does not exist");
        require(doc.issuer == msg.sender, "Only the issuer can revoke");
        require(!doc.isRevoked, "Document is already revoked");

        // Invalidate the document
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
