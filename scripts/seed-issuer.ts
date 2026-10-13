import dotenv from 'dotenv';
dotenv.config();

import jwt from 'jsonwebtoken';
import { ethers } from 'ethers';
import { PrismaClient, Role } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-for-dev';

  // We can use the relayer wallet or a dedicated test issuer address
  const issuerAddress = ethers.getAddress('0x95E40748aa3765041baF8613736dE40aC23FCC92');

  console.log(`Seeding Issuer user in Postgres: ${issuerAddress}`);

  const user = await prisma.user.upsert({
    where: { address: issuerAddress },
    update: {
      role: Role.ISSUER,
    },
    create: {
      address: issuerAddress,
      role: Role.ISSUER,
    },
  });

  const token = jwt.sign(
    {
      id: user.id,
      address: user.address,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  console.log('\n=============================================================');
  console.log('ISSUER TOKEN GENERATED:');
  console.log(`Bearer ${token}`);
  console.log('=============================================================\n');
  console.log('User Record:', user);
}

main()
  .catch((e) => {
    console.error('Error seeding issuer:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
