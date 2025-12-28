import * as Uint8ArrayExtension from '@quentinadam/uint8array-extension';
import CompactSignature from './CompactSignature.ts';
import assert from '@quentinadam/assert';
import { recoverPublicKey } from './secp256k1.ts';
import PublicKey from './PublicKey.ts';
import ensure from '@quentinadam/ensure';

function encodeIntegerElement(value: bigint) {
  const buffer = value === 0n ? new Uint8Array([0]) : Uint8ArrayExtension.fromIntBE(value);
  assert(buffer.length <= 32);
  return Uint8ArrayExtension.concat([new Uint8Array([0x02]), new Uint8Array([buffer.length]), buffer]);
}

export default class Signature extends CompactSignature {
  readonly recovery: number;

  constructor({ r, s, recovery }: { r: bigint; s: bigint; recovery: number }) {
    super({ r, s });
    assert(recovery === 0 || recovery === 1 || recovery === 2 || recovery === 3, 'Recovery must be between 0 and 3');
    this.recovery = recovery;
  }

  override toBytes(): Uint8Array<ArrayBuffer> {
    return Uint8ArrayExtension.concat([
      Uint8ArrayExtension.fromUintBE(this.recovery, 1),
      super.toBytes(),
    ]);
  }

  toCompact(): CompactSignature {
    return new CompactSignature({ r: this.r, s: this.s });
  }

  toDER(): Uint8Array<ArrayBuffer> {
    const r = encodeIntegerElement(this.r);
    const s = encodeIntegerElement(this.s);
    return Uint8ArrayExtension.concat([new Uint8Array([0x30]), new Uint8Array([r.length + s.length]), r, s]);
  }

  recoverPublicKey(hash: Uint8Array<ArrayBuffer>): PublicKey {
    return PublicKey.fromBytes(recoverPublicKey(this.toBytes(), hash));
  }

  static override fromBytes(bytes: Uint8Array<ArrayBuffer>): Signature {
    assert(bytes.length === 65, 'Signature must be 65 bytes long');
    const recovery = ensure(bytes[0]);
    const r = Uint8ArrayExtension.toBigUintBE(bytes.slice(1, 33));
    const s = Uint8ArrayExtension.toBigUintBE(bytes.slice(33, 65));
    return new Signature({ r, s, recovery });
  }
}
