import * as Uint8ArrayExtension from '@quentinadam/uint8array-extension';
import { Point } from '@noble/secp256k1';
import assert, { AssertionError } from '@quentinadam/assert';

export default class PublicKey {
  readonly x: bigint;
  readonly y: bigint;

  constructor({ x, y }: { x: bigint; y: bigint }) {
    this.x = x;
    this.y = y;
  }

  toBytes(compressed = true): Uint8Array<ArrayBuffer> {
    if (compressed) {
      const prefix = (this.y & 1n) === 0n ? 0x02 : 0x03;
      return Uint8ArrayExtension.concat([
        new Uint8Array([prefix]),
        Uint8ArrayExtension.fromUintBE(this.x, 32),
      ]);
    } else {
      return Uint8ArrayExtension.concat([
        new Uint8Array([0x04]),
        Uint8ArrayExtension.fromUintBE(this.x, 32),
        Uint8ArrayExtension.fromUintBE(this.y, 32),
      ]);
    }
  }

  static fromBytes(bytes: Uint8Array<ArrayBuffer>): PublicKey {
    switch (bytes.length) {
      case 33: {
        assert(bytes[0] === 0x02 || bytes[0] === 0x03, 'Invalid compressed public key prefix');
        break;
      }
      case 65: {
        assert(bytes[0] === 0x04, 'Invalid uncompressed public key prefix');
        break;
      }
      default: {
        throw new AssertionError('Public key must be 33 or 65 bytes long');
      }
    }
    const { x, y } = Point.fromBytes(bytes).toAffine();
    return new PublicKey({ x, y });
  }
}
