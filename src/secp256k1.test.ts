import assert from '@quentinadam/assert';
import { getPublicKey, recoverPublicKey, sign } from './secp256k1.ts';
import PrivateKey from './PrivateKey.ts';
import Signature from './Signature.ts';
import PublicKey from './PublicKey.ts';

const privateKeyBytes = Uint8Array.fromHex('f50c596aa05b8e18c8b85f3f56171c0f95f59d1493ef31991f1095a9397206d0');
const privateKey = PrivateKey.fromBytes(privateKeyBytes);
const hash = Uint8Array.fromHex('0ef816a80c1baf78a7a47d0eeb3bb1eed3b99f170daa8db7a346b427d2f78e19');
const expectedSignature = new Signature({
  r: 0xde35da1aac43444559be59ad7b610c95399db605b5ac233b638d1133220a5cfbn,
  s: 0x68f870835fbd584b2ebe99cbf23f9350d89dc7c45a6a3c45cd3820c389fee00cn,
  recovery: 0,
});
const expectedPublicKey = new PublicKey({
  x: 0x8f70745c06511c9ec851a7fcfafb687bd7a65b861e2b5a6e0836314120346758n,
  y: 0x5c61824ced28ec9ce39d3094590ce5b9fad8e788bbe5d0adab32aa83190b71fcn,
});

Deno.test('sign', () => {
  const { r, s, recovery } = sign(hash, privateKeyBytes);
  assert(r === expectedSignature.r);
  assert(s === expectedSignature.s);
  assert(recovery === expectedSignature.recovery);
});
Deno.test('getPublicKey (uncompressed)', () => {
  const publicKey = getPublicKey(privateKeyBytes, false);
  assert(publicKey.toHex() === expectedPublicKey.toBytes(false).toHex());
});
Deno.test('getPublicKey (compressed)', () => {
  const publicKey = getPublicKey(privateKeyBytes, true);
  assert(publicKey.toHex() === expectedPublicKey.toBytes(true).toHex());
});
Deno.test('recoverPublicKey', () => {
  const publicKey = recoverPublicKey(expectedSignature.toBytes(), hash, false);
  assert(publicKey.toHex() === expectedPublicKey.toBytes(false).toHex());
});
Deno.test('PrivateKey.sign', () => {
  const { r, s, recovery } = privateKey.sign(hash);
  assert(r === expectedSignature.r);
  assert(s === expectedSignature.s);
  assert(recovery === expectedSignature.recovery);
});
Deno.test('PrivateKey.getPublicKey (uncompressed)', () => {
  const publicKey = privateKey.getPublicKey();
  assert(publicKey.toBytes(false).toHex() === expectedPublicKey.toBytes(false).toHex());
});
Deno.test('PrivateKey.getPublicKey (compressed)', () => {
  const publicKey = privateKey.getPublicKey();
  assert(publicKey.toBytes(true).toHex() === expectedPublicKey.toBytes(true).toHex());
});
Deno.test('Signature.recoverPublicKey', () => {
  const publicKey = expectedSignature.recoverPublicKey(hash);
  assert(publicKey.toBytes(false).toHex() === expectedPublicKey.toBytes(false).toHex());
});
