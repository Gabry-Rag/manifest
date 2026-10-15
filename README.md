# SevenLab Device Authorization Manifest

This repository hosts the compiled and cryptographically signed authorization manifest (`auth_manifest.bin`) for SevenLab.

## Structure
- `auth_manifest.bin`: Binary 7LMF v3 container containing authorized machine hashes, entitlement flags, quorum verification vectors, and cryptographic signature.
- `auth_manifest.sig`: Detached Ed25519 signature.
- `version.json`: Cryptographic integrity metadata and digests.

## Verification
All artifacts are signed by the Device Manifest Authority and verified using the public key:
`2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12`
