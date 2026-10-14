import axios from 'axios';
import FormData from 'form-data';
import fs from 'fs';

async function main() {
  const token =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Ijc2MTg2ZjU3LTBmY2EtNDE0OS1iNDViLWJhMTg4ZjFiOTE2MiIsImFkZHJlc3MiOiIweDk1RTQwNzQ4YWEzNzY1MDQxYmFGODYxMzczNmRFNDBhQzIzRkNDOTIiLCJyb2xlIjoiSVNTVUVSIiwiaWF0IjoxNzkxOTA3NDgxLCJleHAiOjE3OTQ0OTk0ODF9.AXdjUIyUbJ8OtPLZf1kGAwkn-GyMCXfsE-hmGxutrw4';

  console.log('=== TEST 1: Issuing Fresh Document with HMAC-SHA256 Watermark ===');
  // Create a unique file buffer
  const sampleContent = `HMAC Forensic Credential issued at ${new Date().toISOString()} for Citizen 0xFF9c1176A9AA26973742F953742A04A91ED28948`;
  const formIssue = new FormData();
  formIssue.append('file', Buffer.from(sampleContent, 'utf8'), 'hmac_credential.pdf');
  // Test requirement 3: using citizenAddress
  formIssue.append('citizenAddress', '0xFF9c1176A9AA26973742F953742A04A91ED28948');
  formIssue.append('docType', 'AccreditedDegree');
  formIssue.append('ttlDays', '365');

  const issueRes = await axios.post('http://localhost:5000/api/documents/issue', formIssue, {
    headers: {
      ...formIssue.getHeaders(),
      Authorization: `Bearer ${token}`,
    },
  });

  const docId = issueRes.data.documentId || issueRes.data.document?.id || issueRes.data.metadata?.id;
  console.log('Issued Document ID:', docId);
  console.log('Sepolia Tx Hash:', issueRes.data.txHash);

  console.log('\n=== TEST 2: Downloading Official Stamped File ===');
  const dlRes = await axios.get(`http://localhost:5000/api/documents/${docId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
    responseType: 'arraybuffer',
  });
  const authenticFile = Buffer.from(dlRes.data);
  fs.writeFileSync('downloaded_hmac.pdf', authenticFile);
  console.log('Downloaded file size:', authenticFile.length, 'bytes');

  // Verify trailer contains HMAC forensic tag
  const trailerWindow = authenticFile.subarray(Math.max(0, authenticFile.length - 200)).toString('utf8');
  console.log('File Trailer Preview:\n', trailerWindow.trim());

  console.log('\n=== TEST 3: Ephemeral Grant Creation & Atomic View Consumption ===');
  const grantRes = await axios.post(
    `http://localhost:5000/api/documents/${docId}/grant`,
    {
      granteeLabel: 'Acme Background Check Corp',
      maxViews: 1,
      ttlMinutes: 60,
    },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  const grantToken = grantRes.data.grantToken;
  console.log('Grant Created. Token:', grantToken);

  // 1st View (Expected: 200 OK)
  const view1 = await axios.get(`http://localhost:5000/api/documents/verify-grant/${grantToken}`);
  console.log('View 1 HTTP Status:', view1.status);
  console.log('View 1 verificationStatus:', view1.data.verificationStatus);

  // 2nd View (Expected: 410 Gone / SELF_DESTRUCTED)
  try {
    await axios.get(`http://localhost:5000/api/documents/verify-grant/${grantToken}`);
    console.error('ERROR: Expected 410 Gone!');
  } catch (err: any) {
    console.log('View 2 HTTP Status:', err.response?.status);
    console.log('View 2 Body:', JSON.stringify(err.response?.data, null, 2));
  }

  console.log('\n=== TEST 4: Verifying Authentic Stamped File (Direct Hash Match) ===');
  const formAuth = new FormData();
  formAuth.append('file', authenticFile, 'downloaded_hmac.pdf');
  const verifyAuth = await axios.post('http://localhost:5000/api/documents/verify', formAuth, {
    headers: formAuth.getHeaders(),
  });
  console.log('Authentic Verification Status:', verifyAuth.data.verificationStatus);
  console.log('Authentic Verification isValid:', verifyAuth.data.isValid);
  console.log('Matched Document ID:', verifyAuth.data.document?.id);

  console.log('\n=== TEST 5: Zero-Trust IDOR Protection (Forged / Unauthenticated Tag) ===');
  // Upload a random file or a forged tag with fake HMAC
  const forgedTag = Buffer.from(`\n%%CONSORTIUM-FORENSIC-TAG:${docId}.${'f'.repeat(64)}%%\n`, 'utf8');
  const forgedFile = Buffer.concat([Buffer.from('Some forged content'), forgedTag]);
  const formForged = new FormData();
  formForged.append('file', forgedFile, 'forged.pdf');
  const verifyForged = await axios.post('http://localhost:5000/api/documents/verify', formForged, {
    headers: formForged.getHeaders(),
  });
  console.log('Forged Tag Verification Status:', verifyForged.data.verificationStatus);
  console.log('Forged Tag isValid:', verifyForged.data.isValid);
  console.log('Forensics Triggered?', Boolean(verifyForged.data.forensics));

  console.log('\n=== TEST 6: Tamper Forensics (Body Tampered with Valid HMAC Watermark) ===');
  const tamperedFile = Buffer.from(authenticFile);
  // Modify byte 10 in the document body
  tamperedFile[10] = tamperedFile[10] === 0x41 ? 0x42 : 0x41;
  const formTamper = new FormData();
  formTamper.append('file', tamperedFile, 'tampered_hmac.pdf');
  const verifyTamper = await axios.post('http://localhost:5000/api/documents/verify', formTamper, {
    headers: formTamper.getHeaders(),
  });
  console.log('Tampered Verification Status:', verifyTamper.data.verificationStatus);
  console.log('Tampered Verification isValid:', verifyTamper.data.isValid);
  console.log('Tamper Forensics Payload:', JSON.stringify(verifyTamper.data.forensics, null, 2));

  console.log('\n=== TEST 7: On-Chain Revocation with Reason ===');
  const revokeRes = await axios.post(
    `http://localhost:5000/api/documents/${docId}/revoke`,
    {
      reason: 'Credential revoked due to disciplinary action audit',
    },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  console.log('Revocation Tx Hash:', revokeRes.data.txHash);
  console.log('Revocation Status:', revokeRes.data.isRevoked);

  console.log('\n=== TEST 8: Verifying Revoked File ===');
  const formRevoked = new FormData();
  formRevoked.append('file', authenticFile, 'downloaded_hmac.pdf');
  const verifyRevoked = await axios.post('http://localhost:5000/api/documents/verify', formRevoked, {
    headers: formRevoked.getHeaders(),
  });
  console.log('Post-Revocation verificationStatus:', verifyRevoked.data.verificationStatus);
  console.log('Post-Revocation isValid:', verifyRevoked.data.isValid);
  console.log('Post-Revocation onChain Record:', JSON.stringify(verifyRevoked.data.onChain, null, 2));
}

main().catch(console.error);
