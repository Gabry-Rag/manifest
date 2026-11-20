# SevenLab Device Authorization Manifest

This repository hosts the compiled and cryptographically signed authorization manifest (`auth_manifest.bin`) for SevenLab.

## Structure
- `auth_manifest.bin`: Binary 7LMF v4 container containing authorized machine hashes, entitlement flags, quorum verification vectors, and cryptographic signature.
- `auth_manifest.sig`: Detached Ed25519 signature.
- `version.json`: Cryptographic integrity metadata, digests, `version_policies`, and offline lease defaults (rolling 14-day TTL).
- `onboarding_allowlist.json`: Zero-Knowledge SHA-256 identity hash allowlist used by the relay gate.

## Verification
All artifacts are signed by the Device Manifest Authority and verified using the official public key:
`7b094398579995aa70abcf53a8adb9b1b907da58090bc48af7142d4c8ab25196`

## Device Onboarding Relay
Public self-service workstation accreditation requests (`device-request` issues) are processed by `.github/workflows/relay_device_request.yml` via `.github/scripts/relay_core.js`:
- **Requirements**: GitHub **Issues** must be enabled on this repository and the repository secret **`SIDE_VALIDATION_RELAY_PAT`** must be configured to dispatch `device-onboarding` to `Gabry-Rag/SevenLab-SideValidation` (`repository_dispatch` with `<= 10` top-level `client_payload` keys and nested `meta`).
- **Privacy & Status Feedback**: Issue bodies are redacted immediately (`🔒 *Contenuto payload rimosso automaticamente dal gateway SevenLab.*`, retaining only a non-sensitive `<!-- sevenlab-ref:... -->` deduplication marker) and issues are closed/locked upon processing; SevenLab-SideValidation publishes Zero-Knowledge status comments (`<!-- sevenlab-accreditation:... -->`) via `MANIFEST_REPO_PAT` (`issues:write` + `contents:write`).
- **CI Integrity Gate**: `.github/workflows/verify_manifest.yml` runs `npm test` and `npm run verify:manifest` (zero-dep `node:crypto` Ed25519 verification on every published manifest).
- **Encrypted Envelope (`7LS1`)**: Release clients seal hardware vectors via X25519 + HKDF-SHA256 + ChaCha20-Poly1305 before opening an issue so plaintext hardware fingerprints never appear publicly.

## License & Intellectual Property
**Copyright © 2024–2027 Gabriele Ragonesi (SevenLab). All rights reserved.**  
Exclusive intellectual property pursuant to **art. 12-bis L. 633/1941**. See [LICENSE](LICENSE).
