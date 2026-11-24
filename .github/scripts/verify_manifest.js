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
const EXT_MAGIC = '7LEX';
const MAX_7LEX_EXTENSIONS = 64;
const TAG_GLOBAL_POLICY = 0x0001;
const TAG_APPROVED_CORE_TEXT_HASHES = 0x0002;
const TAG_RECORD_METADATA = 0x0003;
const HEX64_RE = /^[a-f0-9]{64}$/i;

function parseAndValidate7Lex(extSlice) {
  if (extSlice.length < 8) {
    throw new Error(`7LMF v5 container missing 7LEX header (${extSlice.length}B)`);
  }
  const extMagic = extSlice.subarray(0, 4).toString('ascii');
  if (extMagic !== EXT_MAGIC) {
    throw new Error(`Invalid 7LMF v5 extension magic '${extMagic}', expected '${EXT_MAGIC}'`);
  }
  const extCount = extSlice.readUInt32LE(4);
  if (extCount > MAX_7LEX_EXTENSIONS) {
    throw new Error(`7LEX TLV extension count ${extCount} exceeds limit ${MAX_7LEX_EXTENSIONS}`);
  }
  let cursor = 8;
  const decoded = { globalPolicy: null, approvedCoreTextHashes: [], recordMetadata: [], extCount };
  for (let i = 0; i < extCount; i += 1) {
    if (cursor + 6 > extSlice.length) {
      throw new Error(`Truncated 7LEX TLV entry #${i} at offset ${cursor}`);
    }
    const tag = extSlice.readUInt16LE(cursor);
    const valLen = extSlice.readUInt32LE(cursor + 2);
    cursor += 6;
    if (cursor + valLen > extSlice.length) {
      throw new Error(`7LEX TLV entry #${i} length ${valLen} exceeds signed payload`);
    }
    const val = extSlice.subarray(cursor, cursor + valLen);
    cursor += valLen;

    if (tag === TAG_GLOBAL_POLICY) {
      const parsed = JSON.parse(val.toString('utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('7LEX TAG_GLOBAL_POLICY must decode to a JSON object');
      }
      decoded.globalPolicy = parsed;
    } else if (tag === TAG_APPROVED_CORE_TEXT_HASHES) {
      if (valLen % 32 !== 0) {
        throw new Error(`7LEX TAG_APPROVED_CORE_TEXT_HASHES length ${valLen} must be a multiple of 32`);
      }
      for (let off = 0; off < valLen; off += 32) {
        decoded.approvedCoreTextHashes.push(val.subarray(off, off + 32).toString('hex'));
      }
    } else if (tag === TAG_RECORD_METADATA) {
      const parsed = JSON.parse(val.toString('utf8'));
      if (!Array.isArray(parsed)) {
        throw new Error('7LEX TAG_RECORD_METADATA must decode to a JSON array');
      }
      decoded.recordMetadata = parsed;
    }
  }
  if (cursor !== extSlice.length) {
    throw new Error(`7LMF v5 extension cursor ${cursor} does not align with signature start (${extSlice.length})`);
  }
  return decoded;
}

function verifyManifestContainer({
  bin,
  detachedSig,
  ver,
  allowlist,
  pubKeyHex = OFFICIAL_PUBKEY_HEX,
  nowSec = Math.floor(Date.now() / 1000),
}) {
  if (!Buffer.isBuffer(bin) || bin.length < HEADER_SIZE + SIG_SIZE) {
    throw new Error(`auth_manifest.bin too short: ${bin ? bin.length : 0} bytes`);
  }

  const magic = bin.subarray(0, 4).toString('ascii');
  const version = bin.readUInt32LE(4);
  const epoch = bin.readBigUInt64LE(8);
  const issuedAtTsHeader = bin.readBigUInt64LE(16);
  const validUntilTsHeader = bin.readBigUInt64LE(24);
  const numAuth = bin.readUInt32LE(32);
  const numRev = bin.readUInt32LE(36);

  if (magic !== '7LMF') {
    throw new Error(`Invalid magic '${magic}', expected '7LMF'`);
  }
  if (version !== 4 && version !== 5) {
    throw new Error(`Invalid container version ${version}, expected 4 or 5 (7LMF v4/v5 exclusive)`);
  }
  if (epoch <= 0n) {
    throw new Error(`Invalid manifest epoch ${epoch}: must be > 0`);
  }

  const baseRecordsEnd = HEADER_SIZE + AUTH_RECORD_SIZE * numAuth + REV_RECORD_SIZE * numRev;
  if (bin.length < baseRecordsEnd + SIG_SIZE) {
    throw new Error(`Truncated container (${bin.length}B < minimum ${baseRecordsEnd + SIG_SIZE}B)`);
  }

  const sigStart = bin.length - SIG_SIZE;
  let extensions = null;
  if (version === 4) {
    if (bin.length !== baseRecordsEnd + SIG_SIZE) {
      throw new Error(`7LMF v4 length mismatch: got ${bin.length}, expected ${baseRecordsEnd + SIG_SIZE}`);
    }
  } else {
    extensions = parseAndValidate7Lex(bin.subarray(baseRecordsEnd, sigStart));
  }

  const payload = bin.subarray(0, sigStart);
  const embeddedSig = bin.subarray(sigStart);
  if (!Buffer.isBuffer(detachedSig) || embeddedSig.length !== SIG_SIZE || detachedSig.length !== SIG_SIZE || !detachedSig.equals(embeddedSig)) {
    throw new Error('Detached auth_manifest.sig does not match embedded container signature.');
  }

  const normalizedPubHex = String(pubKeyHex || '').toLowerCase();
  const pubRaw = Buffer.from(normalizedPubHex, 'hex');
  const pubKey = crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, pubRaw]),
    format: 'der',
    type: 'spki',
  });

  if (!crypto.verify(null, payload, pubKey, embeddedSig)) {
    throw new Error('Ed25519 signature verification failed against issuer public key.');
  }

  const binSha = crypto.createHash('sha256').update(bin).digest('hex').toLowerCase();
  const payloadSha = crypto.createHash('sha256').update(payload).digest('hex').toLowerCase();

  if (!HEX64_RE.test(String(ver.manifest_sha256 || '')) || String(ver.manifest_sha256).toLowerCase() !== binSha) {
    throw new Error(`version.json manifest_sha256 mismatch: expected ${binSha}, got ${ver.manifest_sha256}`);
  }
  if (!HEX64_RE.test(String(ver.payload_sha256 || '')) || String(ver.payload_sha256).toLowerCase() !== payloadSha) {
    throw new Error(`version.json payload_sha256 mismatch: expected ${payloadSha}, got ${ver.payload_sha256}`);
  }
  if (Number(ver.manifest_size_bytes) !== bin.length) {
    throw new Error(`version.json manifest_size_bytes mismatch: expected ${bin.length}, got ${ver.manifest_size_bytes}`);
  }
  if (Number(ver.payload_size_bytes) !== payload.length) {
    throw new Error(`version.json payload_size_bytes mismatch: expected ${payload.length}, got ${ver.payload_size_bytes}`);
  }
  if (Number(ver.version) !== version) {
    throw new Error(`version.json version mismatch: expected ${version}, got ${ver.version}`);
  }
  if (BigInt(ver.manifest_epoch) !== epoch) {
    throw new Error(`version.json manifest_epoch mismatch: expected ${epoch}, got ${ver.manifest_epoch}`);
  }
  if (Number(ver.num_authorized) !== numAuth || Number(ver.num_revoked) !== numRev) {
    throw new Error(`version.json record counts (${ver.num_authorized}/${ver.num_revoked}) mismatch binary (${numAuth}/${numRev})`);
  }
  if (!HEX64_RE.test(String(ver.issuer_public_key || '')) || String(ver.issuer_public_key).toLowerCase() !== normalizedPubHex) {
    throw new Error(`version.json issuer_public_key mismatch: ${ver.issuer_public_key}`);
  }
  if (!HEX64_RE.test(String(ver.state_merkle_root || ''))) {
    throw new Error(`version.json invalid state_merkle_root: ${ver.state_merkle_root}`);
  }

  const validUntilTs = Number(ver.valid_until_ts);
  const issuedAtMs = Date.parse(String(ver.issued_at_utc || ''));
  const validUntilMs = Date.parse(String(ver.valid_until_utc || ''));
  if (!Number.isFinite(validUntilTs) || validUntilTs <= 0 || !Number.isFinite(validUntilMs)) {
    throw new Error('version.json missing valid expiry window (valid_until_ts / valid_until_utc).');
  }
  if (BigInt(Math.trunc(validUntilTs)) !== validUntilTsHeader) {
    throw new Error(`version.json valid_until_ts (${validUntilTs}) mismatches binary header (${validUntilTsHeader}).`);
  }
  if (Number.isFinite(issuedAtMs)) {
    const issuedAtSec = Math.floor(issuedAtMs / 1000);
    if (BigInt(issuedAtSec) !== issuedAtTsHeader) {
      throw new Error(`version.json issued_at_utc (${issuedAtSec}) mismatches binary header (${issuedAtTsHeader}).`);
    }
  }
  if (Number.isFinite(issuedAtMs) && validUntilMs <= issuedAtMs) {
    throw new Error('version.json valid_until_utc must be strictly after issued_at_utc.');
  }
  if (validUntilTs < nowSec) {
    throw new Error(`Manifest has expired (valid_until_ts=${validUntilTs} < now=${nowSec}).`);
  }

  if (allowlist.allow_unknown_user_onboarding !== false) {
    throw new Error('onboarding_allowlist.json must explicitly set allow_unknown_user_onboarding === false');
  }
  if (!Array.isArray(allowlist.allowed_user_hashes)) {
    throw new Error('onboarding_allowlist.json must contain allowed_user_hashes array');
  }
  for (const entry of allowlist.allowed_user_hashes) {
    if (!HEX64_RE.test(String(entry || ''))) {
      throw new Error(`onboarding_allowlist.json contains non-64-hex hash entry: ${String(entry)}`);
    }
  }

  return { version, epoch, numAuth, numRev, size: bin.length, extensions };
}

function main() {
  const repoRoot = path.resolve(__dirname, '../..');
  const binPath = path.join(repoRoot, 'auth_manifest.bin');
  const sigPath = path.join(repoRoot, 'auth_manifest.sig');
  const verPath = path.join(repoRoot, 'version.json');
  const allowPath = path.join(repoRoot, 'onboarding_allowlist.json');

  for (const p of [binPath, sigPath, verPath, allowPath]) {
    if (!fs.existsSync(p)) {
      console.error(`[FAIL] Missing required artifact: ${path.basename(p)}`);
      process.exit(1);
    }
  }

  try {
    const summary = verifyManifestContainer({
      bin: fs.readFileSync(binPath),
      detachedSig: fs.readFileSync(sigPath),
      ver: JSON.parse(fs.readFileSync(verPath, 'utf8')),
      allowlist: JSON.parse(fs.readFileSync(allowPath, 'utf8')),
    });
    console.log(
      `[OK] 7LMF v${summary.version} manifest verified (epoch=${summary.epoch}, auth=${summary.numAuth}, rev=${summary.numRev}, size=${summary.size}B, hashes/expiry/allowlist/Ed25519 valid).`
    );
  } catch (err) {
    console.error(`[FAIL] ${err.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  OFFICIAL_PUBKEY_HEX,
  HEADER_SIZE,
  AUTH_RECORD_SIZE,
  REV_RECORD_SIZE,
  SIG_SIZE,
  EXT_MAGIC,
  TAG_GLOBAL_POLICY,
  TAG_APPROVED_CORE_TEXT_HASHES,
  TAG_RECORD_METADATA,
  parseAndValidate7Lex,
  verifyManifestContainer,
};
