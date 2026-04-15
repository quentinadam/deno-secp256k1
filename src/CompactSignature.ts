import { assert } from '@quentinadam/assert';
import { concat, fromUintBE, toBigUintBE } from '@quentinadam/uint8array-extension';

export class CompactSignature {
  readonly r: bigint;
  readonly s: bigint;

  constructor({ r, s }: { r: bigint; s: bigint }) {
    assert(r >= 0n && r < 1n << 256n, 'r must be between 0 and 2^256 - 1');
    assert(s >= 0n && s < 1n << 256n, 's must be between 0 and 2^256 - 1');
    this.r = r;
    this.s = s;
  }

  toBytes(): Uint8Array<ArrayBuffer> {
    return concat([fromUintBE(this.r, 32), fromUintBE(this.s, 32)]);
  }

  static fromBytes(bytes: Uint8Array<ArrayBuffer>): CompactSignature {
    assert(bytes.length === 64, 'Compact signature must be 64 bytes long');
    const r = toBigUintBE(bytes.slice(0, 32));
    const s = toBigUintBE(bytes.slice(32, 64));
    return new CompactSignature({ r, s });
  }
}
