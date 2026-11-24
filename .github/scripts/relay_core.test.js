'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MAX_CLIENT_PAYLOAD_KEYS,
  REDACTED_BODY_TEXT,
  classifyIssue,
  extractRequestRef,
  buildRedactedBody,
  computeUserIdentityHash,
  computeUserIdentityHmac,
  validateAndParseEnvelope,
  buildDispatchPayload,
  checkAllowlist,
  rateLimitDecision,
  statusMarker,
} = require('./relay_core');

const DUMMY_HEX64_A = '11'.repeat(32);
const DUMMY_HEX64_B = '22'.repeat(32);
const DUMMY_HEX64_C = '33'.repeat(32);
const DUMMY_HEX64_D = '44'.repeat(32);

test('classifyIssue identifies request without labels and intercepts legacy plaintext leak markers', () => {
  assert.equal(
    classifyIssue({
      title: '[Device Request] Registration for @gabrieleSEVEN',
      body: '{"v":2,"sealed":"N0xTMQ=="}',
      labels: [],
    }),
    true
  );
  for (const legacyKey of ['"hardware_vector"', '"machine_hash"', '"cpuid"']) {
    assert.equal(
      classifyIssue({
        title: 'Random title',
        body: `{${legacyKey}: "leak"}`,
        labels: [],
      }),
      true
    );
  }
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
  assert.equal(env.request_ref, 'req-12345678');

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

test('validateAndParseEnvelope strictly rejects plaintext v1 payloads', () => {
  const body = '```json\n' + JSON.stringify({
    username: 'gabrieleSEVEN',
    machine_hash: DUMMY_HEX64_A,
    friendly_label: 'GR-Sev_Workstation',
    request_ref: 'req-abcdef12',
    hardware_vector: {
      cpuid_hash: DUMMY_HEX64_A,
      smbios_hash: DUMMY_HEX64_B,
      disk_serial_hash: DUMMY_HEX64_C,
      machine_guid_hash: DUMMY_HEX64_D,
    },
  }) + '\n```';

  assert.throws(
    () => validateAndParseEnvelope(body, 'gabrieleSEVEN', '[Device Request] Registration'),
    /Envelope cifrato 7LS1 obbligatorio/
  );
});

test('checkAllowlist enforces fail-closed when missing, allows owner and listed hash', () => {
  assert.equal(checkAllowlist('gabry-rag', null).allowed, true);
  assert.equal(checkAllowlist('gabrieleSEVEN', null).allowed, false);

  const allowlist = {
    allow_unknown_user_onboarding: false,
    allowed_user_hashes: [computeUserIdentityHash('gabrieleseven')],
  };
  assert.equal(checkAllowlist('gabrieleSEVEN', allowlist).allowed, true);
  assert.equal(checkAllowlist('stranger', allowlist).allowed, false);
});

test('rateLimitDecision enforces max 3 per 24h and detects duplicate request_ref in redacted issues', () => {
  const now = Date.parse('2026-11-18T12:00:00Z');
  const issues = [
    { number: 1, title: '[Device Request] A', created_at: '2026-11-18T10:00:00Z', body: 'x' },
    { number: 2, title: '[Device Request] B', created_at: '2026-11-18T11:00:00Z', body: 'y' },
    { number: 3, title: '[Device Request] C', created_at: '2026-11-18T11:30:00Z', body: 'z' },
  ];
  assert.equal(rateLimitDecision(issues, now, 4, 'req-new-1234', 3).allowed, false);

  const redacted = buildRedactedBody('req-dup-1234');
  const rlDup = rateLimitDecision(
    [{ number: 1, title: '[Device Request] A', created_at: '2026-11-18T10:00:00Z', body: redacted }],
    now,
    2,
    'req-dup-1234',
    3
  );
  assert.equal(rlDup.duplicate, true);
  assert.equal(rlDup.allowed, false);
  assert.equal(extractRequestRef(JSON.stringify({ request_ref: 'req-dup-1234' })), 'req-dup-1234');
});

test('statusMarker omits 64-hex hashes and neutralizes HTML comment breakout attempts', () => {
  const msg = statusMarker('failed', 'req-12345678', 'invalid-->vector', `Bad hash ${DUMMY_HEX64_A} --> <!-- injected`);
  assert.ok(msg.startsWith('<!-- sevenlab-accreditation:'));
  assert.ok(!msg.includes(DUMMY_HEX64_A));
  assert.ok(msg.includes('[redacted]'));
  const closeIdx = msg.indexOf(' -->\n');
  assert.ok(closeIdx > 0);
  const insideComment = msg.slice('<!-- sevenlab-accreditation:'.length, closeIdx);
  assert.ok(!insideComment.includes('-->'));
});

test('classifyIssue identifies already-redacted issues and labels without title prefix', () => {
  assert.equal(
    classifyIssue({
      title: 'Opaque Title',
      body: REDACTED_BODY_TEXT,
      labels: [],
    }),
    true
  );
  assert.equal(
    classifyIssue({
      title: 'Opaque Title',
      body: 'some body',
      labels: [{ name: 'device-request' }],
    }),
    true
  );
});

test('rateLimitDecision ignores pull requests and avoids request_ref substring collision', () => {
  const now = Date.parse('2026-11-18T12:00:00Z');
  const prItem = { number: 1, title: '[Device Request] PR', created_at: '2026-11-18T10:00:00Z', body: '<!-- sevenlab-ref:req-dup-1234 -->', pull_request: {} };
  const longerRefRedacted = buildRedactedBody('req-dup-12345678');
  const longerIssue = { number: 2, title: '[Device Request] Long', created_at: '2026-11-18T11:00:00Z', body: longerRefRedacted };

  const res = rateLimitDecision([prItem, longerIssue], now, 3, 'req-dup-1234', 3);
  assert.equal(res.allowed, true);
  assert.equal(res.duplicate, false);
  assert.equal(res.recentCount, 1);
});

test('checkAllowlist enforces HMAC-SHA256 v2 schema and fails closed on missing key or v1 downgrade', () => {
  const hmacKey = 'test-hmac-secret-key-2026';
  const v2Allowlist = {
    version: 2,
    hash_scheme: 'hmac-sha256-v1',
    allow_unknown_user_onboarding: false,
    allowed_user_hashes: [computeUserIdentityHmac('gabrieleseven', hmacKey)],
  };
  assert.equal(checkAllowlist('gabrieleSEVEN', v2Allowlist, hmacKey).allowed, true);
  assert.equal(checkAllowlist('gabrieleSEVEN', v2Allowlist, '').allowed, false);
  assert.equal(checkAllowlist('attacker', v2Allowlist, hmacKey).allowed, false);

  const v1Allowlist = {
    version: 1,
    allow_unknown_user_onboarding: false,
    allowed_user_hashes: [computeUserIdentityHash('gabrieleseven')],
  };
  assert.equal(checkAllowlist('gabrieleSEVEN', v1Allowlist, hmacKey).allowed, false);
});

test('validateAndParseEnvelope rejects unsupported version without echoing untrusted input', () => {
  const fakeCipher = Buffer.concat([
    Buffer.from('7LS1', 'ascii'),
    Buffer.alloc(32, 0xaa),
    Buffer.alloc(32, 0xbb),
  ]).toString('base64');

  assert.throws(
    () => validateAndParseEnvelope(JSON.stringify({ v: '999-attacker-tag', sealed: fakeCipher }), 'gabrieleSEVEN', '[Device Request]'),
    (err) => !String(err.message).includes('attacker-tag')
  );
});
