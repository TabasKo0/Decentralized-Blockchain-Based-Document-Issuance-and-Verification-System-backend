import axios from 'axios';
import FormData from 'form-data';
import fs from 'fs';

async function main() {
  const docId = 'f84619cc-3aff-4248-a09c-ce5021384ea3';
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Ijc2MTg2ZjU3LTBmY2EtNDE0OS1iNDViLWJhMTg4ZjFiOTE2MiIsImFkZHJlc3MiOiIweDk1RTQwNzQ4YWEzNzY1MDQxYmFGODYxMzczNmRFNDBhQzIzRkNDOTIiLCJyb2xlIjoiSVNTVUVSIiwiaWF0IjoxNzkxOTA3NDgxLCJleHAiOjE3OTQ0OTk0ODF9.AXdjUIyUbJ8OtPLZf1kGAwkn-GyMCXfsE-hmGxutrw4';

  console.log('=== TEST 1: Ephemeral Grant Creation ===');
  const grantRes = await axios.post(`http://localhost:5000/api/documents/${docId}/grant`, {
    recipientName: 'Acme Background Check Corp',
    maxViews: 1,
    validityMinutes: 60
  }, { headers: { Authorization: `Bearer ${token}` } });
  console.log('Grant Created:', JSON.stringify(grantRes.data, null, 2));

  const grantToken = grantRes.data.grantToken;

  console.log('\n=== TEST 2: Ephemeral Grant 1st View (Expected: 200 OK) ===');
  const view1 = await axios.get(`http://localhost:5000/api/documents/verify-grant/${grantToken}`);
  console.log('View 1 HTTP Status:', view1.status);
  console.log('verificationStatus:', view1.data.verificationStatus);
  console.log('viewsConsumed:', view1.data.viewsConsumed, 'remainingViews:', view1.data.remainingViews);

  console.log('\n=== TEST 3: Ephemeral Grant 2nd View (Expected: 410 Gone / SELF_DESTRUCTED) ===');
  try {
    await axios.get(`http://localhost:5000/api/documents/verify-grant/${grantToken}`);
    console.error('ERROR: Expected 410 Gone!');
  } catch (err: any) {
    console.log('View 2 HTTP Status:', err.response?.status);
    console.log('View 2 Body:', JSON.stringify(err.response?.data, null, 2));
  }

  console.log('\n=== TEST 4: Downloading & Verifying Authentic Stamped File (Zero-Hint Watermark) ===');
  const dlRes = await axios.get(`http://localhost:5000/api/documents/${docId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
    responseType: 'arraybuffer'
  });
  const authenticFile = Buffer.from(dlRes.data);
  fs.writeFileSync('downloaded_test.pdf', authenticFile);
  console.log('Downloaded stamped file bytes:', authenticFile.length);
  const formAuth = new FormData();
  formAuth.append('file', authenticFile, 'downloaded_test.pdf');
  const verifyAuth = await axios.post('http://localhost:5000/api/documents/verify', formAuth, {
    headers: formAuth.getHeaders()
  });
  console.log('Authentic Verification Status:', verifyAuth.data.verificationStatus);
  console.log('Authentic Verification isValid:', verifyAuth.data.isValid);
  console.log('Detected Document ID:', verifyAuth.data.document?.id);

  console.log('\n=== TEST 5: Tamper Forensics (Zero-Hint Watermarked Modified File) ===');
  // Create a tampered version of the authentic file by modifying bytes in the body while keeping the watermark trailer
  const tamperedFile = Buffer.from(authenticFile);
  // tamper byte 10
  tamperedFile[10] = tamperedFile[10] === 0x41 ? 0x42 : 0x41;
  fs.writeFileSync('tampered_test.pdf', tamperedFile);

  const formTamper = new FormData();
  formTamper.append('file', tamperedFile, 'tampered_test.pdf');
  const verifyTamper = await axios.post('http://localhost:5000/api/documents/verify', formTamper, {
    headers: formTamper.getHeaders()
  });
  console.log('Tampered Verification Status:', verifyTamper.data.verificationStatus);
  console.log('Tampered Verification isValid:', verifyTamper.data.isValid);
  console.log('Tampered Forensics:', JSON.stringify(verifyTamper.data.forensics, null, 2));

  console.log('\n=== TEST 6: On-Chain Revocation with Reason ===');
  const revokeRes = await axios.post(`http://localhost:5000/api/documents/${docId}/revoke`, {
    reason: 'Credential revoked due to disciplinary action audit'
  }, { headers: { Authorization: `Bearer ${token}` } });
  console.log('Revocation Response:', JSON.stringify(revokeRes.data, null, 2));

  console.log('\n=== TEST 7: Verifying Revoked File ===');
  const formRevoked = new FormData();
  formRevoked.append('file', authenticFile, 'downloaded_test.pdf');
  const verifyRevoked = await axios.post('http://localhost:5000/api/documents/verify', formRevoked, {
    headers: formRevoked.getHeaders()
  });
  console.log('Post-Revocation verificationStatus:', verifyRevoked.data.verificationStatus);
  console.log('Post-Revocation isValid:', verifyRevoked.data.isValid);
  console.log('Post-Revocation onChain:', JSON.stringify(verifyRevoked.data.onChain, null, 2));
}

main().catch(console.error);
