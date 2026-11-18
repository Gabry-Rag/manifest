'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MAX_CLIENT_PAYLOAD_KEYS,
  classifyIssue,
  computeUserIdentityHash,
  computeCompositeHash,
  validateAndParseEnvelope,
  buildDispatchPayload,
  checkAllowlist,
  rateLimitDecision,
  statusMarker,
} = require('./relay_core');

const CPUID = '11'.repeat(32);
const SMBIOS = '22'.repeat(32);
const DISK = '33'.repeat(32);
const GUID = '44'.repeat(32);
const COMP = computeCompositeHash(CPUID, SMBIOS, DISK, GUID);

test('classifyIssue identifies request without labels (non-collaborator author)', () => {
  assert.equal(
    classifyIssue({
      title: '[Device Request] Registration for @gabrieleSEVEN',
      body: '{"v":2,"sealed":"N0xTMQ=="}',
      labels: [],
    }),
    true
  );
  assert.equal(
    classifyIssue({
      title: 'General bug report',
      body: 'Something broke in Revit',
      labels: [],
    }),
    false
  );
});

test('validateAndParseEnvelope accepts sealed v2 envelope and enforces <=10 keys', () => {
  const fakeCipher = Buffer.concat([
    Buffer.from('7LS1', 'ascii'),
    Buffer.alloc(32, 0xaa),
    Buffer.alloc(32, 0xbb),
  ]).toString('base64');

  const env = validateAndParseEnvelope(
    JSON.stringify({ v: 2, request_ref: 'req-12345678', sealed: fakeCipher }),
    'gabrieleSEVEN',
    '[Device Request] Registration for @gabrieleSEVEN'
  );
  assert.equal(env.mode, 'sealed_v2');
  assert.equal(env.username, 'gabrieleSEVEN');

  const payload = buildDispatchPayload(env, 42, '2026-11-18T05:00:00Z');
  assert.ok(Object.keys(payload).length <= MAX_CLIENT_PAYLOAD_KEYS);
  assert.equal(payload.meta.issue_number, 42);
  assert.equal(payload.meta.request_ref, 'req-12345678');
});

test('validateAndParseEnvelope rejects identity spoofing even on sealed envelope', () => {
  const fakeCipher = Buffer.concat([
    Buffer.from('7LS1', 'ascii'),
    Buffer.alloc(32, 0xaa),
    Buffer.alloc(32, 0xbb),
  ]).toString('base64');

  assert.throws(
    () =>
      validateAndParseEnvelope(
        JSON.stringify({ v: 2, username: 'otherUser', sealed: fakeCipher }),
        'attacker',
        '[Device Request] Registration for @otherUser'
      ),
    /Identity spoofing rejected/
  );
});

test('validateAndParseEnvelope accepts plaintext v1 and buildDispatchPayload stays <=10 keys', () => {
  const body = '```json\n' + JSON.stringify({
    username: 'gabrieleSEVEN',
    machine_hash: COMP,
    friendly_label: 'GR-Sev_Workstation',
    request_ref: 'req-abcdef12',
    hardware_vector: {
      cpuid_hash: CPUID,
      smbios_hash: SMBIOS,
      disk_serial_hash: DISK,
      machine_guid_hash: GUID,
    },
  }) + '\n```';

  const env = validateAndParseEnvelope(body, 'gabrieleSEVEN', '[Device Request] Registration');
  assert.equal(env.mode, 'plaintext_v1');
  const payload = buildDispatchPayload(env, 99, '2026-11-18T05:00:00Z');
  assert.ok(Object.keys(payload).length <= MAX_CLIENT_PAYLOAD_KEYS);
  assert.equal(payload.meta.issue_number, 99);
  assert.equal(payload.label, 'GR-Sev_Workstation');
});

test('validateAndParseEnvelope rejects composite mismatch and non-ASCII label', () => {
  assert.throws(
    () =>
      validateAndParseEnvelope(
        JSON.stringify({
          machine_hash: 'ff'.repeat(32),
          hardware_vector: { cpuid_hash: CPUID, smbios_hash: SMBIOS, disk_serial_hash: DISK, machine_guid_hash: GUID },
        }),
        'gabrieleSEVEN',
        '[Device Request]'
      ),
    /Composite SHA-256 mismatch/
  );

  assert.throws(
    () =>
      validateAndParseEnvelope(
        JSON.stringify({
          machine_hash: COMP,
          friendly_label: 'Postazione Città',
          hardware_vector: { cpuid_hash: CPUID, smbios_hash: SMBIOS, disk_serial_hash: DISK, machine_guid_hash: GUID },
        }),
        'gabrieleSEVEN',
        '[Device Request]'
      ),
    /Etichetta postazione non valida/
  );
});

test('checkAllowlist enforces fail-closed when missing, allows owner and listed hash', () => {
  assert.equal(checkAllowlist('gabry-rag', null, null).allowed, true);
  assert.equal(checkAllowlist('gabrieleSEVEN', null, null).allowed, false);

  const allowlist = {
    allow_unknown_user_onboarding: false,
    allowed_user_hashes: [computeUserIdentityHash('gabrieleseven')],
  };
  assert.equal(checkAllowlist('gabrieleSEVEN', allowlist, null).allowed, true);
  assert.equal(checkAllowlist('stranger', allowlist, null).allowed, false);
});

test('rateLimitDecision enforces max 3 per 24h and detects duplicate request_ref', () => {
  const now = Date.parse('2026-11-18T12:00:00Z');
  const issues = [
    { number: 1, title: '[Device Request] A', created_at: '2026-11-18T10:00:00Z', body: 'x' },
    { number: 2, title: '[Device Request] B', created_at: '2026-11-18T11:00:00Z', body: 'y' },
    { number: 3, title: '[Device Request] C', created_at: '2026-11-18T11:30:00Z', body: 'z' },
  ];
  assert.equal(rateLimitDecision(issues, now, 4, 'req-new-1234', 3).allowed, false);
  assert.equal(
    rateLimitDecision([{ number: 1, title: '[Device Request] A', created_at: '2026-11-18T10:00:00Z', body: 'req-dup-1234' }], now, 2, 'req-dup-1234', 3).duplicate,
    true
  );
});

test('statusMarker omits 64-hex hashes and emits machine-readable comment', () => {
  const msg = statusMarker('failed', 'req-12345678', 'invalid_vector', `Bad hash ${COMP}`);
  assert.ok(msg.startsWith('<!-- sevenlab-accreditation:'));
  assert.ok(!msg.includes(COMP));
  assert.ok(msg.includes('[redacted]'));
});
