'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OFFICIAL_PUBKEY_HEX = '7b094398579995aa70abcf53a8adb9b1b907da58090bc48af7142d4c8ab25196';
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const HEADER_SIZE = 72;
const AUTH_RECORD_SIZE = 208;
const REV_RECORD_SIZE = 32;
const SIG_SIZE = 64;

function fail(msg) {
  console.error(`[FAIL] ${msg}`);
  process.exit(1);
}

const repoRoot = path.resolve(__dirname, '../..');
const binPath = path.join(repoRoot, 'auth_manifest.bin');
const sigPath = path.join(repoRoot, 'auth_manifest.sig');
const verPath = path.join(repoRoot, 'version.json');
const allowPath = path.join(repoRoot, 'onboarding_allowlist.json');

for (const p of [binPath, sigPath, verPath, allowPath]) {
  if (!fs.existsSync(p)) {
    fail(`Missing required artifact: ${path.basename(p)}`);
  }
}

const bin = fs.readFileSync(binPath);
if (bin.length < HEADER_SIZE + SIG_SIZE) {
  fail(`auth_manifest.bin too short: ${bin.length} bytes`);
}

const magic = bin.subarray(0, 4).toString('ascii');
const version = bin.readUInt32LE(4);
const epoch = bin.readBigUInt64LE(8);
const numAuth = bin.readUInt32LE(32);
const numRev = bin.readUInt32LE(36);

if (magic !== '7LMF') {
  fail(`Invalid magic '${magic}', expected '7LMF'`);
}
if (version !== 4) {
  fail(`Invalid container version ${version}, expected 4 (7LMF v4 exclusive)`);
}

const expectedPayloadLen = HEADER_SIZE + (AUTH_RECORD_SIZE * numAuth) + (REV_RECORD_SIZE * numRev);
if (bin.length !== expectedPayloadLen + SIG_SIZE) {
  fail(`Container length mismatch: got ${bin.length}, expected ${expectedPayloadLen + SIG_SIZE}`);
}

// Dynamic slicing per 7LMF v4 spec (never hardcode slice offsets)
const payload = bin.subarray(0, bin.length - SIG_SIZE);
const embeddedSig = bin.subarray(bin.length - SIG_SIZE);
const detachedSig = fs.readFileSync(sigPath);

if (detachedSig.length !== SIG_SIZE || !detachedSig.equals(embeddedSig)) {
  fail('Detached auth_manifest.sig does not match embedded container signature.');
}

const pubRaw = Buffer.from(OFFICIAL_PUBKEY_HEX, 'hex');
const pubKey = crypto.createPublicKey({
  key: Buffer.concat([SPKI_ED25519_PREFIX, pubRaw]),
  format: 'der',
  type: 'spki',
});

if (!crypto.verify(null, payload, pubKey, embeddedSig)) {
  fail('Ed25519 signature verification failed against official issuer public key.');
}

const ver = JSON.parse(fs.readFileSync(verPath, 'utf8'));
const binSha = crypto.createHash('sha256').update(bin).digest('hex');
const payloadSha = crypto.createHash('sha256').update(payload).digest('hex');

if (![binSha, payloadSha].includes(String(ver.manifest_sha256 || '').toLowerCase())) {
  fail(`version.json manifest_sha256 mismatch: ${ver.manifest_sha256}`);
}
if (Number(ver.num_authorized) !== numAuth || Number(ver.num_revoked) !== numRev) {
  fail(`version.json record counts (${ver.num_authorized}/${ver.num_revoked}) mismatch binary (${numAuth}/${numRev})`);
}
if (String(ver.issuer_public_key || '').toLowerCase() !== OFFICIAL_PUBKEY_HEX) {
  fail(`version.json issuer_public_key mismatch: ${ver.issuer_public_key}`);
}

const allowlist = JSON.parse(fs.readFileSync(allowPath, 'utf8'));
if (!Array.isArray(allowlist.allowed_user_hashes)) {
  fail('onboarding_allowlist.json must contain allowed_user_hashes array');
}

console.log(
  `[OK] 7LMF v4 manifest verified (epoch=${epoch}, auth=${numAuth}, rev=${numRev}, size=${bin.length}B, sig=Ed25519 valid).`
);
