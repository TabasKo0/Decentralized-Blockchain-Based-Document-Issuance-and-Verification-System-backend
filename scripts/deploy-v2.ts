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

  if (!rpcUrl || !privateKey) {
    throw new Error('SEPOLIA_RPC_URL and SEPOLIA_PRIVATE_KEY must be set in .env');
  }

  const formattedKey = privateKey.trim().startsWith('0x') ? privateKey.trim() : `0x${privateKey.trim()}`;
  const provider = new ethers.JsonRpcProvider(rpcUrl, 11155111, { staticNetwork: true });
  const deployer = new ethers.Wallet(formattedKey, provider);

  console.log(`=============================================================`);
  console.log(`Deploying DocumentIssuanceConsortium v2 to Sepolia`);
  console.log(`Deployer Address : ${deployer.address}`);
  const balance = await provider.getBalance(deployer.address);
  console.log(`Deployer Balance : ${ethers.formatEther(balance)} ETH`);
  console.log(`=============================================================`);

  // Load compiled artifact
  const artifactPath = path.resolve(
    __dirname,
    '../artifacts/contracts/DocumentIssuanceConsortium.sol/DocumentIssuanceConsortium.json'
  );
  const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));

  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, deployer);

  console.log('Broadcasting deployment transaction...');
  const contract = await factory.deploy();
  console.log(`Deployment Tx: ${contract.deploymentTransaction()?.hash}`);
  console.log('Waiting for contract deployment confirmation...');

  await contract.waitForDeployment();
  const newContractAddress = await contract.getAddress();
  console.log(`\n🎉 Contract v2 Deployed Successfully to Sepolia!`);
  console.log(`New Contract Address: ${newContractAddress}`);

  // Authorize deployer as an issuer
  console.log(`\nAuthorizing relayer ${deployer.address} as an ISSUER on the new contract...`);
  const authTx = await (contract as any).addIssuer(deployer.address);
  console.log(`Auth Tx Hash: ${authTx.hash}`);
  await authTx.wait();

  const isAuthorized = await (contract as any).isIssuer(deployer.address);
  console.log(`Relayer isIssuer on new contract: ${isAuthorized}`);

  // Update .env file
  const envPath = path.resolve(__dirname, '../.env');
  if (fs.existsSync(envPath)) {
    let envContent = fs.readFileSync(envPath, 'utf8');
    if (envContent.includes('CONTRACT_ADDRESS=')) {
      envContent = envContent.replace(
        /CONTRACT_ADDRESS="[^"]*"/,
        `CONTRACT_ADDRESS="${newContractAddress}"`
      );
    } else {
      envContent += `\nCONTRACT_ADDRESS="${newContractAddress}"\n`;
    }
    fs.writeFileSync(envPath, envContent, 'utf8');
    console.log(`Updated CONTRACT_ADDRESS in .env with ${newContractAddress}`);
  }

  console.log(`=============================================================`);
}

main().catch((err) => {
  console.error('Deployment failed:', err);
  process.exit(1);
});
