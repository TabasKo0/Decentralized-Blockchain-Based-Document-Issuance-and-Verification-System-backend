# External Services Setup & Web3 Architecture Guide

This guide provides a comprehensive walkthrough for configuring all external services, environment variables, and understanding the role of **Web3** across the backend and the upcoming frontend development phases.

---

## 1. External Services Setup (`.env`)

To run the backend against live testnets, IPFS, and a relational database, you must configure the environment variables defined in `.env`.

Here is an overview of the required variables:

```env
DATABASE_URL="postgresql://user:password@localhost:5432/mydb"
SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID"
SEPOLIA_PRIVATE_KEY="YOUR_EXPORTED_SEPOLIA_ACCOUNT_PRIVATE_KEY"
JWT_SECRET="YOUR_SUPER_SECRET_JWT_KEY"
MASTER_KMS_KEY="YOUR_SERVER_MASTER_KMS_KEY_256BIT"
PINATA_API_KEY="YOUR_PINATA_API_KEY"
PINATA_SECRET_API_KEY="YOUR_PINATA_SECRET_API_KEY"
```

---

### Step-by-Step Service Configuration

### A. PostgreSQL Database (`DATABASE_URL`)
* **Role**: Stores off-chain metadata, citizen/issuer accounts, role mappings, encrypted Shamir key shares, and audit logs.
* **Option 1 (Cloud - Recommended & Free)**:
  1. Sign up for a free managed Postgres service like [Supabase](https://supabase.com) or [Neon](https://neon.tech).
  2. Create a new project.
  3. Copy the pooled/direct PostgreSQL connection string.
* **Option 2 (Local)**:
  1. Install PostgreSQL locally or run via Docker:
     ```bash
     docker run --name pg-doc-system -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres
     ```
  2. Set `DATABASE_URL="postgresql://postgres:postgres@localhost:5432/doc_system?schema=public"`
* **Initialize Prisma Schema**:
  ```bash
  npx prisma migrate dev --name init
  npx prisma generate
  ```

---

### B. Pinata / IPFS (`PINATA_API_KEY`, `PINATA_SECRET_API_KEY`)
* **Role**: Decentralized file storage. When an issuer creates an encrypted document payload, the backend uploads it to IPFS via Pinata and retrieves a deterministic `ipfsHash` (CID).
* **Setup**:
  1. Go to [Pinata Cloud](https://www.pinata.cloud/) and sign up for a free account.
  2. In the dashboard, navigate to **API Keys** -> **New Key**.
  3. Grant Admin permissions (or Pinning permissions).
  4. Copy both:
     * `API Key` -> `PINATA_API_KEY`
     * `API Secret` -> `PINATA_SECRET_API_KEY`

---

### C. Ethereum Sepolia RPC (`SEPOLIA_RPC_URL`)
* **Role**: Allows the Node.js backend (via `ethers.JsonRpcProvider`) to communicate with the Ethereum Sepolia Testnet to send transactions and read smart contract state.
* **Setup**:
  1. Create a free account on [Infura](https://www.infura.io/) or [Alchemy](https://www.alchemy.com/).
  2. Create an App / API key and select network: **Ethereum Sepolia**.
  3. Copy the HTTPS endpoint URL:
     - Infura: `https://sepolia.infura.io/v3/<YOUR_API_KEY>`
     - Alchemy: `https://eth-sepolia.g.alchemy.com/v2/<YOUR_API_KEY>`
  4. Paste into `SEPOLIA_RPC_URL`.

---

### D. Ethereum Relayer Wallet (`SEPOLIA_PRIVATE_KEY`)
* **Role**: The backend operates as a **Gasless Relayer** on behalf of the consortium. It signs transactions (e.g., `issueDocument`, `revokeDocument`) using an Ethereum account that pays gas fees.
* **Setup**:
  1. Open [MetaMask](https://metamask.io/) (or your preferred Web3 wallet).
  2. Switch to the **Sepolia Test Network** and create a dedicated development account (**DO NOT** use an account holding real mainnet funds).
  3. In MetaMask: Account Details -> **Show Private Key** -> Copy the 64-character hex string (strip any leading `0x` if needed).
  4. Paste into `SEPOLIA_PRIVATE_KEY`.
* **Fund with Testnet ETH**:
  * You need Sepolia ETH to cover transaction gas fees. Obtain free testnet ETH from faucets:
    - [Google Cloud Web3 Sepolia Faucet](https://cloud.google.com/application/web3/faucet/ethereum/sepolia)
    - [Alchemy Sepolia Faucet](https://sepoliafaucet.com/)
    - [Infura Sepolia Faucet](https://www.infura.io/faucet/sepolia)

---

### E. Local Cryptographic Secrets (`JWT_SECRET`, `MASTER_KMS_KEY`)
* **Role**:
  - `JWT_SECRET`: Signs and verifies user session authentication tokens.
  - `MASTER_KMS_KEY`: 256-bit key used by the internal Key Management Service (KMS) for encrypting/decrypting sensitive data and server-side key shares.
* **Setup**:
  Generate two secure 32-byte hex strings using Node.js:
  ```bash
  node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
  node -e "console.log('MASTER_KMS_KEY=' + require('crypto').randomBytes(32).toString('hex'))"
  ```
  Copy the generated strings into `.env`.

---

## 2. The Role of Web3 in this Architecture

In this system, **Web3 is not confined to one layer**—it is split across two distinct stages:

```
+-------------------------------------------------------------------------------+
|                                CURRENT STAGE                                  |
|                                                                               |
|   +-----------------------------------------------------------------------+   |
|   |                        Node.js / Express Backend                      |   |
|   |  - Acts as a Gasless Relayer via ethers.js                            |   |
|   |  - Signs & submits transactions to DocumentIssuanceConsortium.sol     |   |
|   |  - Uploads encrypted files to IPFS (Pinata)                           |   |
|   |  - Manages partial Shamir shares & role authorization                 |   |
|   +-----------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------+
                                       |
                                       v
+-------------------------------------------------------------------------------+
|                                  NEXT STAGE                                   |
|                                                                               |
|   +-----------------------------------------------------------------------+   |
|   |                       Frontend dApp (React / Next.js)                 |   |
|   |  - MetaMask / WalletConnect integration (Identity & Signatures)       |   |
|   |  - Client-side ECIES / AES Decryption (Zero-Knowledge to Server)      |   |
|   |  - Shamir Secret Key Reconstruction in Browser memory                 |   |
|   |  - Direct Public Verification (Querying smart contract on-chain)      |   |
|   +-----------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------+
```

### Stage 1: Backend Web3 (Already Implemented)
1. **Gas Abstraction & Relayer**: Instead of forcing every government issuer or citizen to own cryptocurrency and understand gas limits, the backend's `RelayService` signs and submits transactions (`issueDocument`, `revokeDocument`) using its own funded wallet.
2. **Decentralized Storage (IPFS)**: Encrypted document files are pinned to IPFS, ensuring tamper-proof content addressing via CID hashes.
3. **Smart Contract Verification**: The backend queries the Ethereum blockchain to verify document statuses and validate cryptographic hashes against the tamper-proof ledger.

### Stage 2: Frontend Web3 (Next Stage of Development)
The frontend user interface is where citizen self-sovereignty and end-to-end security are completed:
1. **Wallet Connection (`wagmi`, `viem`, or `ethers.js`)**:
   - Citizens and verifiers connect browser wallets (MetaMask, Rabby, Coinbase Wallet) to authenticate using EIP-4361 ("Sign-In with Ethereum").
2. **Client-Side Decryption & Zero-Knowledge Security**:
   - The backend server should **never** have the power to view a citizen's raw, unencrypted document.
   - The frontend retrieves the encrypted document from IPFS and the encrypted key shares.
   - In browser memory, the frontend reconstructs the AES decryption key via Shamir's Secret Sharing and decrypts the document directly for the user's screen.
3. **Direct Public Verification**:
   - Any third-party verifier (employer, university, border control) can load the dApp, paste a Document ID or drop an issued file, and query the Ethereum smart contract **directly from their browser** without trusting or relying on the backend server.

---

## 3. Verifying the Setup

1. **Compile Smart Contracts**:
   ```bash
   npx hardhat compile
   ```
2. **Run the Full Test Suite**:
   ```bash
   npm test
   ```
   *(All 36 tests across Solidity and TypeScript/Mocha integration layers should pass.)*

3. **Deploy the Smart Contract to Sepolia**:
   ```bash
   npx hardhat ignition deploy ./ignition/modules/DocumentIssuanceConsortium.ts --network sepolia
   ```
4. **Update Deployed Address**:
   Save the deployed contract address from the deployment output into your backend configuration/environment.
