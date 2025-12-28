import * as secp256k1 from '@noble/secp256k1';
import hmacSha256 from '@quentinadam/hash/hmac-sha256';
import ensure from '@quentinadam/ensure';
import assert from '@quentinadam/assert';

export function getPublicKey(privateKey: Uint8Array<ArrayBuffer>, compressed = true): Uint8Array<ArrayBuffer> {
  const publicKey = secp256k1.getPublicKey(privateKey, compressed);
  assert(publicKey.buffer instanceof ArrayBuffer);
  return publicKey as Uint8Array<ArrayBuffer>;
}

export function randomPrivateKey(): Uint8Array<ArrayBuffer> {
  const buffer = secp256k1.utils.randomSecretKey();
  assert(buffer.buffer instanceof ArrayBuffer);
  return buffer as Uint8Array<ArrayBuffer>;
}

export function recoverPublicKey(
  signature: Uint8Array<ArrayBuffer>,
  hash: Uint8Array<ArrayBuffer>,
  compressed = true,
): Uint8Array<ArrayBuffer> {
  let publicKey = secp256k1.recoverPublicKey(signature, hash, { prehash: false });
  if (compressed === false) {
    publicKey = secp256k1.Point.fromBytes(publicKey).toBytes(false);
  }
  assert(publicKey.buffer instanceof ArrayBuffer);
  return publicKey as Uint8Array<ArrayBuffer>;
}

export function sign(
  hash: Uint8Array<ArrayBuffer>,
  privateKey: Uint8Array<ArrayBuffer>,
): { r: bigint; s: bigint; recovery: number } {
  assert(hash.length === 32, 'Hash must be 32 bytes long');
  assert(privateKey.length === 32, 'Private key must be 32 bytes long');
  const _hmacSha256 = secp256k1.hashes.hmacSha256;
  secp256k1.hashes.hmacSha256 = hmacSha256 as (secret: Uint8Array, buffer: Uint8Array) => Uint8Array;
  try {
    const options: secp256k1.ECDSASignOpts = { prehash: false, lowS: true, format: 'recovered', extraEntropy: false };
    const signature = secp256k1.sign(hash, privateKey, options);
    const { r, s, recovery } = secp256k1.Signature.fromBytes(signature, 'recovered');
    return { r, s, recovery: ensure(recovery) };
  } finally {
    secp256k1.hashes.hmacSha256 = _hmacSha256;
  }
}
