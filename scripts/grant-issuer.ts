import 'dotenv/config';
import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const rpcUrl = process.env.SEPOLIA_RPC_URL;
  const privateKey = process.env.SEPOLIA_PRIVATE_KEY;
  const contractAddress = process.env.CONTRACT_ADDRESS || '0xAdba445e10E6d95fc1FA8914DaA8E0E5Ec5cEB9A';
  const targetIssuer = '0x95E40748aa3765041baF8613736dE40aC23FCC92';

  if (!rpcUrl || !privateKey) {
    throw new Error('SEPOLIA_RPC_URL and SEPOLIA_PRIVATE_KEY must be set in .env');
  }

  const formattedKey = privateKey.trim().startsWith('0x') ? privateKey.trim() : `0x${privateKey.trim()}`;
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(formattedKey, provider);

  console.log(`=============================================================`);
  console.log(`Admin Signer Address : ${signer.address}`);
  console.log(`Contract Address     : ${contractAddress}`);
  console.log(`Granting Role To     : ${targetIssuer}`);
  console.log(`=============================================================`);

  // Load ABI from compiled artifact
  const artifactPath = path.resolve(
    __dirname,
    '../artifacts/contracts/DocumentIssuanceConsortium.sol/DocumentIssuanceConsortium.json'
  );
  if (!fs.existsSync(artifactPath)) {
    throw new Error(`Artifact not found at ${artifactPath}. Run 'npm run compile' first.`);
  }

  const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  const contract = new ethers.Contract(contractAddress, artifact.abi, signer);

  // Check current status
  const alreadyIssuer = await contract.isIssuer(targetIssuer);
  if (alreadyIssuer) {
    console.log(`Address ${targetIssuer} is ALREADY an authorized issuer on-chain.`);
    return;
  }

  console.log(`Calling addIssuer(${targetIssuer}) on Sepolia...`);
  const tx = await contract.addIssuer(targetIssuer);
  console.log(`Transaction sent!`);
  console.log(`Tx Hash: ${tx.hash}`);
  console.log(`Waiting for confirmation...`);

  const receipt = await tx.wait();
  console.log(`Transaction confirmed in block #${receipt.blockNumber}!`);
  console.log(`Gas used: ${receipt.gasUsed.toString()}`);

  const confirmedStatus = await contract.isIssuer(targetIssuer);
  console.log(`Verification - isIssuer(${targetIssuer}): ${confirmedStatus}`);
  console.log(`=============================================================`);
}

main().catch((err) => {
  console.error('Error executing grant-issuer script:', err);
  process.exit(1);
});
