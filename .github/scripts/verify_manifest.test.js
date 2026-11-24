'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const {
  HEADER_SIZE,
  EXT_MAGIC,
  TAG_GLOBAL_POLICY,
  TAG_APPROVED_CORE_TEXT_HASHES,
  TAG_RECORD_METADATA,
  verifyManifestContainer,
} = require('./verify_manifest');

function buildSignedFixture({ version = 5, extEntries = [], epoch = 108n }) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const pubKeyHex = spki.subarray(spki.length - 32).toString('hex');

  const nowSec = 1_800_000_000;
  const header = Buffer.alloc(HEADER_SIZE);
  header.write('7LMF', 0, 'ascii');
  header.writeUInt32LE(version, 4);
  header.writeBigUInt64LE(epoch, 8);
  header.writeBigUInt64LE(BigInt(nowSec - 60), 16);
  header.writeBigUInt64LE(BigInt(nowSec + 86400), 24);
  header.writeUInt32LE(0, 32);
  header.writeUInt32LE(0, 36);

  const chunks = [header];
  if (version === 5) {
    const extHdr = Buffer.alloc(8);
    extHdr.write(EXT_MAGIC, 0, 'ascii');
    extHdr.writeUInt32LE(extEntries.length, 4);
    chunks.push(extHdr);
    for (const [tag, valBuf] of extEntries) {
      const th = Buffer.alloc(6);
      th.writeUInt16LE(tag, 0);
      th.writeUInt32LE(valBuf.length, 2);
      chunks.push(th, valBuf);
    }
  }

  const payload = Buffer.concat(chunks);
  const sig = crypto.sign(null, payload, privateKey);
  const bin = Buffer.concat([payload, sig]);

  const ver = {
    version,
    manifest_epoch: Number(epoch),
    manifest_sha256: crypto.createHash('sha256').update(bin).digest('hex'),
    payload_sha256: crypto.createHash('sha256').update(payload).digest('hex'),
    manifest_size_bytes: bin.length,
    payload_size_bytes: payload.length,
    num_authorized: 0,
    num_revoked: 0,
    issuer_public_key: pubKeyHex,
    state_merkle_root: 'aa'.repeat(32),
    issued_at_utc: new Date((nowSec - 60) * 1000).toISOString(),
    valid_until_utc: new Date((nowSec + 86400) * 1000).toISOString(),
    valid_until_ts: nowSec + 86400,
  };
  const allowlist = {
    allow_unknown_user_onboarding: false,
    allowed_user_hashes: ['bb'.repeat(32)],
  };

  return { bin, sig, pubKeyHex, ver, allowlist, nowSec, privateKey };
}

test('verifies valid 7LMF v4 container for backward read compatibility', () => {
  const fix = buildSignedFixture({ version: 4 });
  const res = verifyManifestContainer({
    bin: fix.bin,
    detachedSig: fix.sig,
    ver: fix.ver,
    allowlist: fix.allowlist,
    pubKeyHex: fix.pubKeyHex,
    nowSec: fix.nowSec,
  });
  assert.equal(res.version, 4);
  assert.equal(res.extensions, null);
});

test('verifies valid 7LMF v5 container with 7LEX TLV extensions and skips unknown tags', () => {
  const fix = buildSignedFixture({
    version: 5,
    extEntries: [
      [TAG_GLOBAL_POLICY, Buffer.from(JSON.stringify({ allow_offline_by_default: false, default_offline_lease_hours: 72 }))],
      [TAG_APPROVED_CORE_TEXT_HASHES, Buffer.concat([Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22)])],
      [TAG_RECORD_METADATA, Buffer.from(JSON.stringify([{ machine_hash: 'cc'.repeat(32), tier: 'vdi_online_ephemeral' }]))],
      [0x9999, Buffer.from('FUTURE_EXT')],
    ],
  });
  const res = verifyManifestContainer({
    bin: fix.bin,
    detachedSig: fix.sig,
    ver: fix.ver,
    allowlist: fix.allowlist,
    pubKeyHex: fix.pubKeyHex,
    nowSec: fix.nowSec,
  });
  assert.equal(res.version, 5);
  assert.equal(res.extensions.extCount, 4);
  assert.equal(res.extensions.approvedCoreTextHashes.length, 2);
  assert.equal(res.extensions.recordMetadata[0].tier, 'vdi_online_ephemeral');
});

test('rejects legacy v3 containers and malformed 7LEX TLV blocks', () => {
  const v3 = buildSignedFixture({ version: 3 });
  assert.throws(
    () =>
      verifyManifestContainer({
        bin: v3.bin,
        detachedSig: v3.sig,
        ver: v3.ver,
        allowlist: v3.allowlist,
        pubKeyHex: v3.pubKeyHex,
        nowSec: v3.nowSec,
      }),
    /expected 4 or 5/
  );

  const badHashes = buildSignedFixture({
    version: 5,
    extEntries: [[TAG_APPROVED_CORE_TEXT_HASHES, Buffer.alloc(33, 0xab)]],
  });
  assert.throws(
    () =>
      verifyManifestContainer({
        bin: badHashes.bin,
        detachedSig: badHashes.sig,
        ver: badHashes.ver,
        allowlist: badHashes.allowlist,
        pubKeyHex: badHashes.pubKeyHex,
        nowSec: badHashes.nowSec,
      }),
    /multiple of 32/
  );
});
