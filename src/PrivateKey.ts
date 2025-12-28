import Signature from './Signature.ts';
import { getPublicKey, randomPrivateKey, sign } from './secp256k1.ts';
import PublicKey from './PublicKey.ts';
import assert from '@quentinadam/assert';
import Uint8ArrayExtension from '@quentinadam/uint8array-extension';
import { Point } from '@noble/secp256k1';

export default class PrivateKey {
  readonly #value: bigint;

  constructor(value: bigint) {
    assert(value > 0n, 'Private key must be greater than 0');
    assert(value < Point.CURVE().n, 'Private key must be less than the curve order');
    this.#value = value;
  }

  sign(hash: Uint8Array<ArrayBuffer>): Signature {
    return new Signature(sign(hash, this.toBytes()));
  }

  toBytes(): Uint8Array<ArrayBuffer> {
    return Uint8ArrayExtension.fromUintBE(this.#value, 32);
  }

  static fromBytes(bytes: Uint8Array<ArrayBuffer>): PrivateKey {
    assert(bytes.length === 32, 'Private key must be 32 bytes long');
    const value = new Uint8ArrayExtension(bytes).toBigUintBE();
    return new PrivateKey(value);
  }

  static random(): PrivateKey {
    return new PrivateKey(new Uint8ArrayExtension(randomPrivateKey()).toBigUintBE());
  }

  getPublicKey(): PublicKey {
    return PublicKey.fromBytes(getPublicKey(this.toBytes(), false));
  }
}
