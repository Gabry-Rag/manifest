'use strict';

const crypto = require('crypto');

const SEALED_MAGIC = Buffer.from('7LS1', 'ascii');
const REQUEST_REF_RE = /^[A-Za-z0-9_-]{8,64}$/;
const HEX64_RE = /^[a-f0-9]{64}$/i;
const REF_MARKER_RE = /<!--\s*sevenlab-ref:([A-Za-z0-9_-]{8,64})\s*-->/g;
const USER_IDENTITY_DOMAIN = 'SevenLab-User-Identity-v1:';
const MAX_CLIENT_PAYLOAD_KEYS = 10;
const REDACTED_BODY_TEXT = '🔒 *Contenuto payload rimosso automaticamente dal gateway SevenLab.*';

function stripHex64(text) {
  return String(text || '').replace(/[a-f0-9]{64}/gi, '[redacted]');
}

function sanitizeHtmlCommentPayload(text) {
  return String(text || '')
    .replace(/-->/g, '--\\u003e')
    .replace(/<!--/g, '\\u003c!--');
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

  // Keep legacy plaintext markers and redacted gateway markers so already-redacted
  // onboarding issues still count toward the 24h actor quota.
  const hasEnvelopeOrRedactedMarker =
    body.includes('"sealed"') ||
    body.includes('"hardware_vector"') ||
    body.includes('"machine_hash"') ||
    body.includes('"cpuid"') ||
    body.includes('<!-- sevenlab-ref:') ||
    body.includes('<!-- sevenlab-accreditation:') ||
    body.includes('Contenuto payload rimosso automaticamente dal gateway SevenLab');

  return Boolean(isDeviceTitle || labels.includes('device-request') || hasEnvelopeOrRedactedMarker);
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
    const safeRr = rr.replace(/--+/g, '-');
    return `<!-- sevenlab-ref:${safeRr} -->\n${REDACTED_BODY_TEXT}`;
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

function computeUserIdentityHmac(username, hmacKey) {
  const clean = String(username || '').trim().toLowerCase().replace(/^@+/, '');
  return crypto
    .createHmac('sha256', Buffer.from(String(hmacKey || ''), 'utf8'))
    .update(`${USER_IDENTITY_DOMAIN}${clean}`, 'utf8')
    .digest('hex')
    .toLowerCase();
}

function timingSafeHexEquals(a, b) {
  if (!HEX64_RE.test(String(a || '')) || !HEX64_RE.test(String(b || ''))) {
    return false;
  }
  const bufA = Buffer.from(String(a).toLowerCase(), 'hex');
  const bufB = Buffer.from(String(b).toLowerCase(), 'hex');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
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
      throw new Error('Identity spoofing rejected: issue author does not match payload username.');
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
  if (!Number.isInteger(version) || version !== 2) {
    throw new Error('Versione envelope sealed non supportata (richiesta v2).');
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

function checkAllowlist(issueUser, allowlistObj, hmacKey) {
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

  const cleanHmacKey = typeof hmacKey === 'string' ? hmacKey.trim() : '';
  const isHmacScheme =
    allowlistObj.hash_scheme === 'hmac-sha256-v1' || Number(allowlistObj.version) >= 2;

  let candidateDigest;
  if (isHmacScheme) {
    if (!cleanHmacKey) {
      return {
        allowed: false,
        reason: 'Chiave HMAC allowlist non configurata sul gateway (fail-closed).',
      };
    }
    candidateDigest = computeUserIdentityHmac(cleanUser, cleanHmacKey);
  } else {
    if (cleanHmacKey) {
      return {
        allowed: false,
        reason: 'Allowlist v1 unkeyed rifiutata in modalità HMAC-SHA256 (anti-downgrade).',
      };
    }
    candidateDigest = computeUserIdentityHash(cleanUser);
  }

  for (const rawEntry of hashes) {
    if (timingSafeHexEquals(rawEntry, candidateDigest)) {
      return { allowed: true, reason: isHmacScheme ? 'allowlist_hmac_match' : 'allowlist_match' };
    }
  }

  return {
    allowed: false,
    reason: 'Utente GitHub non presente nella lista autorizzata (anti-flooding gate).',
  };
}

function hasExactRefMarker(bodyText, requestRef) {
  if (!requestRef || typeof bodyText !== 'string') return false;
  REF_MARKER_RE.lastIndex = 0;
  let match;
  while ((match = REF_MARKER_RE.exec(bodyText)) !== null) {
    if (match[1] === requestRef) {
      return true;
    }
  }
  return false;
}

function rateLimitDecision(recentIssues, nowMs, currentIssueNumber, requestRef, maxPer24h = 3) {
  const cutoff = (typeof nowMs === 'number' ? nowMs : Date.now()) - 24 * 3600 * 1000;
  const list = Array.isArray(recentIssues) ? recentIssues : [];
  let recentCount = 0;

  for (const item of list) {
    if (!item || item.pull_request || Number(item.number) === Number(currentIssueNumber)) {
      continue;
    }
    const createdMs = Date.parse(item.created_at || '');
    if (Number.isFinite(createdMs) && createdMs >= cutoff) {
      if (classifyIssue(item)) {
        recentCount += 1;
      }
    }
    const itemBody = typeof item.body === 'string' ? item.body : '';
    if (requestRef && hasExactRefMarker(itemBody, requestRef)) {
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
  const cleanPhase = String(phase || 'failed').trim().toLowerCase().slice(0, 32);
  const payload = {
    v: 1,
    ref: requestRef && REQUEST_REF_RE.test(String(requestRef)) ? String(requestRef) : null,
    phase: cleanPhase,
    updated_at_utc: new Date().toISOString(),
  };
  if (reasonCode) {
    payload.reason_code = sanitizeHtmlCommentPayload(String(reasonCode).trim()).slice(0, 64);
  }
  const safeMsg = sanitizeHtmlCommentPayload(stripHex64(message || '')).slice(0, 300);
  if (safeMsg) {
    payload.message = safeMsg;
  }

  const encodedPayload = sanitizeHtmlCommentPayload(JSON.stringify(payload));
  const marker = `<!-- sevenlab-accreditation:${encodedPayload} -->`;
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
  computeUserIdentityHmac,
  validateAndParseEnvelope,
  buildDispatchPayload,
  checkAllowlist,
  rateLimitDecision,
  statusMarker,
  stripHex64,
};
