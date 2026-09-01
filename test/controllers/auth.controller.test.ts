import { expect } from 'chai';
import type { Request, Response } from 'express';
import { register, login, recoverKey } from '../../src/controllers/auth.controller';
import { prisma } from '../../src/db';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const createMockResponse = () => {
  const res: any = {};
  res.statusCode = 200;
  res.data = null;
  res.status = function (code: number) { this.statusCode = code; return this; };
  res.json = function (data: any) { this.data = data; return this; };
  return res as Response;
};

describe('AuthController', function () {
  let originalFindUnique: any;
  let originalCreate: any;
  let originalHash: any;
  let originalCompare: any;
  let originalSign: any;

  before(function () {
    originalFindUnique = prisma.user.findUnique;
    originalCreate = prisma.user.create;
    originalHash = bcrypt.hash;
    originalCompare = bcrypt.compare;
    originalSign = jwt.sign;
  });

  afterEach(function () {
    prisma.user.findUnique = originalFindUnique;
    prisma.user.create = originalCreate;
    bcrypt.hash = originalHash;
    bcrypt.compare = originalCompare;
    jwt.sign = originalSign;
  });

  describe('Validation Tests', function () {
    it('register should require email and password', async function () {
      const req = { body: { email: 'test@test.com' } } as Request;
      const res = createMockResponse();
      await register(req, res);
      expect((res as any).statusCode).to.equal(400);
      expect((res as any).data.message).to.equal('Email and password required');
    });

    it('login should require email and password', async function () {
      const req = { body: { password: 'pwd' } } as Request;
      const res = createMockResponse();
      await login(req, res);
      expect((res as any).statusCode).to.equal(400);
      expect((res as any).data.message).to.equal('Email and password required');
    });

    it('recoverKey should require email and shareC', async function () {
      const req = { body: { email: 'test@test.com' } } as Request;
      const res = createMockResponse();
      await recoverKey(req, res);
      expect((res as any).statusCode).to.equal(400);
      expect((res as any).data.message).to.equal('Email and shareC required');
    });
  });

  describe('Happy Path', function () {
    it('register should successfully create user and return shares', async function () {
      prisma.user.findUnique = async () => null;
      prisma.user.create = async (args: any) => ({
        id: 'user-id',
        email: args.data.email,
        walletAddress: args.data.walletAddress,
        publicKey: args.data.publicKey,
        encryptedShareB: args.data.encryptedShareB,
        isIssuer: args.data.isIssuer
      }) as any;
      
      bcrypt.hash = async () => 'hashed_pwd' as any;
      jwt.sign = () => 'mock_jwt_token' as any;

      const req = { body: { email: 'new@test.com', password: 'secure', isIssuer: true } } as Request;
      const res = createMockResponse();

      await register(req, res);

      const data = (res as any).data;
      expect(data.success).to.be.true;
      expect(data.token).to.equal('mock_jwt_token');
      expect(data.user.email).to.equal('new@test.com');
      expect(data.user.isIssuer).to.be.true;
      expect(data).to.have.property('shareA');
      expect(data).to.have.property('shareC');
    });

    it('login should return jwt token and encryptedShareB', async function () {
      prisma.user.findUnique = async () => ({
        id: 'user-id',
        email: 'new@test.com',
        passwordHash: 'hashed_pwd',
        walletAddress: '0xabc',
        publicKey: '0xpub',
        encryptedShareB: 'enc_share_b',
        isIssuer: true
      }) as any;

      bcrypt.compare = async () => true as any;
      jwt.sign = () => 'mock_jwt_token' as any;

      const req = { body: { email: 'new@test.com', password: 'secure' } } as Request;
      const res = createMockResponse();

      await login(req, res);

      const data = (res as any).data;
      expect(data.success).to.be.true;
      expect(data.token).to.equal('mock_jwt_token');
      expect(data.user.email).to.equal('new@test.com');
      expect(data.encryptedShareB).to.equal('enc_share_b');
    });
  });
});
