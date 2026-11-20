'use strict';

const crypto = require('crypto');

const SEALED_MAGIC = Buffer.from('7LS1', 'ascii');
const REQUEST_REF_RE = /^[A-Za-z0-9_-]{8,64}$/;
const USER_IDENTITY_DOMAIN = 'SevenLab-User-Identity-v1:';
const MAX_CLIENT_PAYLOAD_KEYS = 10;
const REDACTED_BODY_TEXT = '🔒 *Contenuto payload rimosso automaticamente dal gateway SevenLab.*';

function stripHex64(text) {
  return String(text || '').replace(/[a-f0-9]{64}/gi, '[redacted]');
}

function classifyIssue(issue) {
  const title = String((issue && issue.title) || '');
  const body = String((issue && issue.body) || '');
  const labels = Array.isArray(issue && issue.labels)
    ? issue.labels.map((l) => String((l && l.name) || l || '').toLowerCase())
    : [];

  const isDeviceTitle =
    title.startsWith('[Device Request]') ||
    title.startsWith('[Device Onboarding]') ||
    title.startsWith('[Device Swap]');

  // Keep legacy plaintext markers intentionally so any accidental plaintext leak
  // still triggers immediate body redaction, issue closing, locking, and rejection.
  const hasEnvelopeMarker =
    body.includes('"sealed"') ||
    body.includes('"hardware_vector"') ||
    body.includes('"machine_hash"') ||
    body.includes('"cpuid"');

  return Boolean(isDeviceTitle || labels.includes('device-request') || hasEnvelopeMarker);
}

function extractJsonBody(rawBody) {
  const raw = String(rawBody || '');
  const codeBlockMatch = raw.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  const rawToParse = codeBlockMatch ? codeBlockMatch[1] : raw;
  return JSON.parse(rawToParse.trim());
}

function extractRequestRef(rawBody) {
  try {
    const parsed = extractJsonBody(rawBody);
    if (parsed && typeof parsed === 'object' && parsed.request_ref) {
      const rr = String(parsed.request_ref).trim();
      if (REQUEST_REF_RE.test(rr)) {
        return rr;
      }
    }
  } catch {
    const match = String(rawBody || '').match(/"request_ref"\s*:\s*"([A-Za-z0-9_-]{8,64})"/);
    if (match) {
      return match[1];
    }
  }
  return null;
}

function buildRedactedBody(requestRef) {
  const rr = requestRef ? String(requestRef).trim() : '';
  if (rr && REQUEST_REF_RE.test(rr)) {
    return `<!-- sevenlab-ref:${rr} -->\n${REDACTED_BODY_TEXT}`;
  }
  return REDACTED_BODY_TEXT;
}

function computeUserIdentityHash(username) {
  const clean = String(username || '').trim().toLowerCase().replace(/^@+/, '');
  return crypto
    .createHash('sha256')
    .update(`${USER_IDENTITY_DOMAIN}${clean}`, 'utf8')
    .digest('hex')
    .toLowerCase();
}

function validateAndParseEnvelope(rawBody, issueUser, _issueTitle) {
  const cleanAuthor = String(issueUser || '').trim().replace(/^@+/, '');
  if (!cleanAuthor || !/^[a-zA-Z0-9_.-]{1,64}$/.test(cleanAuthor)) {
    throw new Error('Autore GitHub non valido.');
  }

  const parsed = extractJsonBody(rawBody);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Payload JSON deve essere un oggetto.');
  }

  if (parsed.username) {
    const claimed = String(parsed.username).trim().replace(/^@+/, '');
    if (claimed.toLowerCase() !== cleanAuthor.toLowerCase()) {
      throw new Error(`Identity spoofing rejected: issue author @${cleanAuthor} does not match payload username`);
    }
  }

  let requestRef = null;
  if (parsed.request_ref !== undefined && parsed.request_ref !== null && String(parsed.request_ref).trim() !== '') {
    const rr = String(parsed.request_ref).trim();
    if (!REQUEST_REF_RE.test(rr)) {
      throw new Error('Formato request_ref non valido.');
    }
    requestRef = rr;
  }

  // Strict v2 sealed envelope: {"v": 2, "sealed": "<base64>", "request_ref": "...", "username": "..."}
  if (typeof parsed.sealed !== 'string' || parsed.sealed.trim().length === 0) {
    throw new Error('Envelope cifrato 7LS1 obbligatorio; payload plaintext v1 non supportato.');
  }

  const version = parsed.v === undefined ? 2 : Number(parsed.v);
  if (version !== 2) {
    throw new Error(`Versione envelope sealed non supportata: ${parsed.v}`);
  }
  const sealedB64 = parsed.sealed.trim();
  if (sealedB64.length > 8192 || !/^[A-Za-z0-9+/=]+$/.test(sealedB64)) {
    throw new Error('Formato Base64 envelope sealed non valido.');
  }
  const rawBuf = Buffer.from(sealedB64, 'base64');
  // 4B magic ("7LS1") + 32B ephemeral pubkey + 16B Poly1305 tag + >= 16B ciphertext
  if (rawBuf.length < 4 + 32 + 16 + 16 || rawBuf.length > 4096 + 64) {
    throw new Error('Dimensione envelope sealed fuori intervallo.');
  }
  if (!rawBuf.subarray(0, 4).equals(SEALED_MAGIC)) {
    throw new Error('Magic header envelope sealed non valido (atteso 7LS1).');
  }

  return {
    mode: 'sealed_v2',
    username: cleanAuthor,
    sealed: sealedB64,
    request_ref: requestRef,
  };
}

function buildDispatchPayload(envelope, issueNumber, nowIso) {
  if (!envelope || envelope.mode !== 'sealed_v2') {
    throw new Error('Envelope cifrato 7LS1 obbligatorio per il dispatch.');
  }
  const requestedAt = nowIso || new Date().toISOString();
  const clientPayload = {
    v: 2,
    username: envelope.username,
    sealed: envelope.sealed,
    request_ref: envelope.request_ref || null,
    source_repo: 'manifest',
    meta: {
      issue_number: Number(issueNumber),
      request_ref: envelope.request_ref || null,
      requested_at_utc: requestedAt,
      source_repo: 'manifest',
    },
  };

  const keyCount = Object.keys(clientPayload).length;
  if (keyCount > MAX_CLIENT_PAYLOAD_KEYS) {
    throw new Error(`Internal invariant violated: client_payload has ${keyCount} top-level keys (max ${MAX_CLIENT_PAYLOAD_KEYS}).`);
  }
  return clientPayload;
}

function checkAllowlist(issueUser, allowlistObj) {
  const cleanUser = String(issueUser || '').trim().toLowerCase().replace(/^@+/, '');
  if (!cleanUser) {
    return { allowed: false, reason: 'Identità GitHub mancante.' };
  }
  if (cleanUser === 'gabry-rag') {
    return { allowed: true, reason: 'platform_owner' };
  }

  if (!allowlistObj || typeof allowlistObj !== 'object') {
    return {
      allowed: false,
      reason: 'Allowlist di onboarding assente (fail-closed): contatta l\'amministratore.',
    };
  }

  if (allowlistObj.allow_unknown_user_onboarding === true) {
    return { allowed: true, reason: 'allow_unknown_enabled' };
  }

  const hashes = Array.isArray(allowlistObj.allowed_user_hashes)
    ? allowlistObj.allowed_user_hashes
    : null;

  if (!Array.isArray(hashes)) {
    return {
      allowed: false,
      reason: 'Allowlist utenti non configurata sul nodo pubblico (fail-closed).',
    };
  }

  const normalized = new Set(hashes.map((h) => String(h || '').trim().toLowerCase()));
  const userHash = computeUserIdentityHash(cleanUser);
  if (normalized.has(userHash)) {
    return { allowed: true, reason: 'allowlist_match' };
  }

  return {
    allowed: false,
    reason: 'Utente GitHub non presente nella lista autorizzata (anti-flooding gate).',
  };
}

function rateLimitDecision(recentIssues, nowMs, currentIssueNumber, requestRef, maxPer24h = 3) {
  const cutoff = (typeof nowMs === 'number' ? nowMs : Date.now()) - 24 * 3600 * 1000;
  const list = Array.isArray(recentIssues) ? recentIssues : [];
  let recentCount = 0;
  const marker = requestRef ? `<!-- sevenlab-ref:${requestRef} -->` : null;

  for (const item of list) {
    if (!item || Number(item.number) === Number(currentIssueNumber)) continue;
    const createdMs = Date.parse(item.created_at || '');
    if (Number.isFinite(createdMs) && createdMs >= cutoff) {
      if (classifyIssue(item)) {
        recentCount += 1;
      }
    }
    const itemBody = typeof item.body === 'string' ? item.body : '';
    if (requestRef && ((marker && itemBody.includes(marker)) || itemBody.includes(requestRef))) {
      return {
        allowed: false,
        duplicate: true,
        recentCount,
        reason: 'Richiesta duplicata (request_ref già presente).',
      };
    }
  }

  if (recentCount >= maxPer24h) {
    return {
      allowed: false,
      duplicate: false,
      recentCount,
      reason: `Limite giornaliero superato (${recentCount}/${maxPer24h} richieste nelle ultime 24h).`,
    };
  }

  return { allowed: true, duplicate: false, recentCount, reason: null };
}

function statusMarker(phase, requestRef, reasonCode, message) {
  const cleanPhase = String(phase || 'failed').trim().toLowerCase();
  const payload = {
    v: 1,
    ref: requestRef || null,
    phase: cleanPhase,
    updated_at_utc: new Date().toISOString(),
  };
  if (reasonCode) {
    payload.reason_code = String(reasonCode).trim();
  }
  const safeMsg = stripHex64(message || '').slice(0, 300);
  if (safeMsg) {
    payload.message = safeMsg;
  }

  const marker = `<!-- sevenlab-accreditation:${JSON.stringify(payload)} -->`;
  let human;
  if (cleanPhase === 'relayed') {
    human = '🔒 **SevenLab Relay (`manifest`)**: Richiesta verificata e inoltrata al backend SevenLab-SideValidation.';
  } else if (cleanPhase === 'queued') {
    human = '⏳ **SevenLab SideValidation**: Richiesta acquisita e inserita in coda di approvazione amministratore.';
  } else if (cleanPhase === 'approved') {
    human = '✅ **SevenLab SideValidation**: Postazione approvata e manifest firmato pubblicato.';
  } else if (cleanPhase === 'rejected') {
    human = `❌ **SevenLab SideValidation**: Richiesta respinta.${safeMsg ? ` Motivo: ${safeMsg}` : ''}`;
  } else {
    human = `⚠️ **SevenLab Relay (\`manifest\`)**: Richiesta non inoltrata.${safeMsg ? ` Motivo: ${safeMsg}` : ''}`;
  }
  return `${marker}\n${human}`;
}

module.exports = {
  MAX_CLIENT_PAYLOAD_KEYS,
  REDACTED_BODY_TEXT,
  classifyIssue,
  extractJsonBody,
  extractRequestRef,
  buildRedactedBody,
  computeUserIdentityHash,
  validateAndParseEnvelope,
  buildDispatchPayload,
  checkAllowlist,
  rateLimitDecision,
  statusMarker,
  stripHex64,
};
