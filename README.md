# SevenLab Device Authorization Manifest

This repository hosts the compiled and cryptographically signed authorization manifest (`auth_manifest.bin`) for SevenLab.

## Structure
- `auth_manifest.bin`: Binary 7LMF v2 container containing authorized machine hashes, entitlement flags, quorum verification vectors, and cryptographic signature.
- `auth_manifest.sig`: Detached Ed25519 signature.
- `version.json`: Cryptographic integrity metadata and digests.

## Verification
All artifacts are signed by the Device Manifest Authority and verified using the public key:
`9f78ada70485c96d0e596b326f95423850a52660dadcb55d56a0c1e51f4a0ff2`
