
Here is the complete, exhaustive **`PROJECT.md`** specification file.

You can save this file directly in your project root (`project/PROJECT.md`) or inside `.agents/PROJECT.md`. It contains every single architectural decision, cryptographic pipeline, data model, API contract, smart contract interface, and workflow we have finalized.

---

```markdown
# Project Specification: Decentralized Blockchain-Based Document Issuance and Verification System (Level 2 MVP)

## 1. Executive Summary
A decentralized, gasless, self-sovereign document issuance and verification platform. 

The system enables authorized institutions (e.g., universities, government agencies) to issue tamper-proof, verifiable digital credentials directly to citizens. It uses a **Consortium Blockchain model** with Role-Based Access Control (RBAC), a gasless **Node.js Relay Engine**, off-chain encrypted storage via **IPFS**, and a non-custodial **2-of-3 Shamir’s Secret Sharing (SSS)** key recovery scheme.

---

## 2. Technology Stack & Tooling

| Component | Technology | Purpose |
|---|---|---|
| **Language & Environment** | Node.js (v18+), TypeScript (`tsc`, `tsx`) | End-to-end type safety for cryptography, buffers, and backend logic. |
| **Smart Contract Framework** | Hardhat (TypeScript) | Compilation, local node simulation, TypeChain type generation, unit testing. |
| **Smart Contract Language** | Solidity `^0.8.20` + OpenZeppelin Contracts | On-chain ledger, `AccessControl` (`ISSUER_ROLE`), revocation registry. |
| **Target Network** | Polygon Amoy Testnet *(Primary)* $\to$ Hyperledger Besu *(Docker Upgrade Path)* | EVM-compatible consortium execution environment. |
| **Relay Backend** | Express.js, TypeScript | REST API, session management, and gasless transaction relayer using Ethers.js. |
| **Database & ORM** | PostgreSQL + Prisma ORM | Stores user auth, public identity mappings, and encrypted SSS Share B. |
| **Decentralized Storage** | IPFS via Pinata SDK | Content-addressed storage for encrypted document blobs. |
| **Key Recovery Engine** | `@digitaldefiance/secrets` | 2-of-3 Shamir’s Secret Sharing threshold cryptography. |
| **Document Encryption** | `AES-256-GCM` (Native Crypto) + `eth-crypto` (ECIES) | Hybrid Envelope Encryption for fast, secure file handling. |
| **Authentication** | `bcrypt` + `jsonwebtoken` (JWT) | Secure password hashing and stateless API authorization. |

---

## 3. Data Boundaries & Storage Architecture


```

┌───────────────────────────────────┬───────────────────────────────────┬───────────────────────────────────┐
│        PostgreSQL Database        │          IPFS (Pinata)            │       Blockchain (Solidity)       │
├───────────────────────────────────┼───────────────────────────────────┼───────────────────────────────────┤
│ • User ID, Email, Password Hash   │ • Encrypted PDF Blob              │ • Document CID Hash (bytes32)     │
│ • User Wallet Address             │   (Ciphertext via AES-256-GCM)    │ • Issuer Address (address)        │
│ • User Public Key (ECIES)         │ • Encrypted Session Key           │ • Citizen Address (address)       │
│ • SSS Share B (Encrypted)         │   (AES key locked via Citizen PK) │ • Document Type String            │
│ • Role Flags (isIssuer, isAdmin)  │ • AES Initialization Vector (IV)  │ • Issuance Timestamp (uint256)    │
│ • Non-sensitive off-chain caches  │ • Auth Tag (GCM integrity)        │ • Revocation Status (bool)        │
│                                   │                                   │ • isOfficial Flag (bool)          │
└───────────────────────────────────┴───────────────────────────────────┴───────────────────────────────────┘

```

---

## 4. Cryptographic Specifications

### A. Key Management: 2-of-3 Shamir's Secret Sharing (SSS)
At user registration, a 256-bit private key is generated and split into 3 mathematical shares using a $(2, 3)$ threshold:
* **Share A (Device Share):** Sent to the client and stored in local storage / session.
* **Share B (Consortium Server Share):** Encrypted with the server's `MASTER_KMS_KEY` and persisted in PostgreSQL.
* **Share C (Recovery Share):** Exported once to the user as a backup alphanumeric recovery code.

* **Reconstruction Rule:** Any 2 shares ($\text{Share A} + \text{Share B}$ OR $\text{Share B} + \text{Share C}$) reconstruct the private key in memory during active sessions. No single database or breach compromises the user's private key.

### B. Hybrid Envelope Encryption Pipeline
* **Issuance Encryption (Authority $\to$ Citizen):**
  1. Generate random 256-bit symmetric session key: $K_{\text{AES}}$.
  2. Encrypt raw PDF payload using $K_{\text{AES}}$ via `AES-256-GCM` $\implies \text{Ciphertext} + \text{IV} + \text{AuthTag}$.
  3. Encrypt $K_{\text{AES}}$ using the Citizen’s Public Key via `eth-crypto` (ECIES) $\implies \text{EncryptedKey}$.
  4. Bundle JSON payload ` { ciphertext, encryptedKey, iv, authTag } ` and upload to IPFS.
* **Citizen Decryption (Local):**
  1. Download payload from IPFS via CID.
  2. Decrypt $\text{EncryptedKey}$ using reconstructed Citizen Private Key $\implies K_{\text{AES}}$.
  3. Decrypt $\text{Ciphertext}$ using $K_{\text{AES}}$, $\text{IV}$, and $\text{AuthTag}$ via `AES-256-GCM` $\implies$ Plaintext PDF.

---

## 5. Smart Contract Interface (`DocumentIssuanceConsortium.sol`)

### Roles
* `DEFAULT_ADMIN_ROLE`: Consortium Admin (can grant/revoke `ISSUER_ROLE`).
* `ISSUER_ROLE`: Whitelisted institutions permitted to issue legally valid documents.

### Data Structures & State
```solidity
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

```

### Core Functions

1. `issueDocument(bytes32 _documentHash, address _citizen, string calldata _docType)`

* *Access:* `onlyRole(ISSUER_ROLE)`
* *Behavior:* Validates unique hash, stores record with `isOfficial = true`, pushes hash to `citizenDocuments[_citizen]`, emits `DocumentIssued`.

2. `uploadPersonalDocument(bytes32 _documentHash, string calldata _docType)`

* *Access:* Public / any authenticated user
* *Behavior:* Stores record with `issuer = msg.sender`, `citizen = msg.sender`, `isOfficial = false`, pushes hash to `citizenDocuments[msg.sender]`.

3. `revokeDocument(bytes32 _documentHash)`

* *Access:* `issuer == msg.sender`
* *Behavior:* Sets `isRevoked = true`, emits `DocumentRevoked`.

4. `getCitizenDocuments(address _citizen)`

* *Access:* Public View
* *Returns:* `bytes32[]` array of all document hashes assigned to that citizen.

---

## 6. Database Schema (`prisma/schema.prisma`)

```prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id               String   @id @default(uuid())
  email            String   @unique
  passwordHash     String
  
  // Public Identity / Web3 identifiers
  walletAddress    String   @unique
  publicKey        String   @unique
  
  // SSS Share B (Encrypted with server MASTER_KMS_KEY)
  encryptedShareB  String
  
  // System Roles
  isIssuer         Boolean  @default(false)
  isAdmin          Boolean  @default(false)
  
  createdAt        DateTime @default(now())
  updatedAt        DateTime @updatedAt
}

```

---

## 7. Node.js Backend API Contract

### Authentication (`/api/auth`)

* `POST /api/auth/register`
* **Body:** `{ email, password }`
* **Process:** Generates keypair, splits into 3 SSS shares, encrypts Share B, saves user to DB.
* **Response:** `{ token, user: { id, email, walletAddress, publicKey }, shareA, shareC }`
* `POST /api/auth/login`
* **Body:** `{ email, password }`
* **Process:** Validates password hash, returns JWT + encrypted Share B.
* **Response:** `{ token, user, encryptedShareB }`
* `POST /api/auth/recover-key`
* **Body:** `{ email, shareC }`
* **Process:** Validates user, decrypts Share B, combines with Share C to reconstruct key.
* **Response:** `{ success: true, reconstructedPrivateKey }`

### Documents & Issuance (`/api/documents`)

* `POST /api/documents/issue` *(Issuer Only)*
* **Headers:** `Authorization: Bearer <JWT>`
* **Body:** `multipart/form-data` (`file`, `citizenWalletAddress`, `docType`)
* **Process:** Fetches citizen public key, performs hybrid envelope encryption, uploads to Pinata IPFS, invokes Node.js Relay Funder Wallet to call `issueDocument()` on-chain.
* **Response:** `{ success: true, txHash, ipfsCID, documentHash }`
* `POST /api/documents/upload-personal` *(Citizen)*
* **Headers:** `Authorization: Bearer <JWT>`
* **Body:** `multipart/form-data` (`file`, `docType`)
* **Process:** Encrypts file with citizen public key, pins to IPFS, relays `uploadPersonalDocument()` to contract.
* **Response:** `{ success: true, txHash, ipfsCID }`
* `GET /api/documents/my-documents` *(Citizen)*
* **Headers:** `Authorization: Bearer <JWT>`
* **Process:** Reads smart contract `getCitizenDocuments(walletAddress)` and returns on-chain metadata.
* **Response:** `[{ documentHash, ipfsCID, docType, issuer, issuedAt, isOfficial, isRevoked }]`
* `POST /api/documents/revoke` *(Issuer Only)*
* **Body:** `{ documentHash }`
* **Process:** Relay sends `revokeDocument()` transaction on-chain.
* **Response:** `{ success: true, txHash }`

### Public Verification (`/api/verify`)

* `GET /api/verify/:documentHash` *(Public)*
* **Process:** Queries smart contract `documents(documentHash)` directly.
* **Response:** `{ exists: true, isOfficial: true, issuer: "0x...", issuedAt: 1718000000, isRevoked: false }`

---

## 8. Step-by-Step Execution Plan

### Phase 1: Environment & Toolchain Initialization

* Hardhat TypeScript setup (`npx hardhat init`).
* TypeScript configurations (`tsconfig.json`) & npm scripts.
* Prisma PostgreSQL migration (`npx prisma db push`).

### Phase 2: Smart Contract Engineering & Unit Testing

* Create `contracts/DocumentIssuanceConsortium.sol` with OpenZeppelin `AccessControl`.
* Write Hardhat tests in `test/DocumentIssuance.test.ts` verifying RBAC, issuance, self-upload, and revocation.
* Compile and produce TypeChain types.

### Phase 3: Cryptography Services

* Implement `src/services/crypto.service.ts`:
* SSS `splitKey()` and `combineShares()`.
* AES-256-GCM file encryption/decryption.
* ECIES session key wrapping/unwrapping.
* Server-side KMS envelope encryption for Share B.

### Phase 4: Decentralized Relay & IPFS Integration

* Implement `src/services/ipfs.service.ts` (Pinata upload/download wrapper).
* Implement `src/services/relay.service.ts` (Ethers.js provider, Funder Wallet signer, contract invocation).

### Phase 5: Express.js Controllers & API Routing

* Implement auth controllers, JWT middlewares, document handling routes, and error handlers in `src/controllers/` and `src/routes/`.
* Connect API to Prisma and services.

### Phase 6: End-to-End API Integration Testing

* Execute full API test cycle using automated test scripts or Postman:

1. Register citizen $\to$ Receive Share A and Share C.
2. Register & authorize issuer $\to$ Grant `ISSUER_ROLE`.
3. Issuer issues encrypted degree $\to$ Pinned to IPFS, logged on-chain.
4. Citizen fetches & decrypts document using Share A + B.
5. Simulate device loss $\to$ Recover using Share B + C.
6. Public verification check of document hash.
