# @quentinadam/secp256k1

[![JSR][jsr-image]][jsr-url] [![NPM][npm-image]][npm-url] [![CI][ci-image]][ci-url]

A simple secp256k1 library that wraps [jsr:@noble/secp256k1](https://jsr.io/@noble/secp256k1).

## Usage

```ts
import * as secp256k1 from '@quentinadam/secp256k1';

const privateKey = randomPrivateKey();
const hash = new Uint8Array(32);

const { r, s, recovery } = secp256k1.sign(hash, privateKey);
```

```ts
import { PrivateKey } from '@quentinadam/secp256k1';

const privateKey = PrivateKey.random();
const hash = new Uint8Array(32);

const { r, s, recovery } = privateKey.sign(hash);
```

[ci-image]: https://img.shields.io/github/actions/workflow/status/quentinadam/deno-secp256k1/ci.yml?branch=main&logo=github&style=flat-square
[ci-url]: https://github.com/quentinadam/deno-secp256k1/actions/workflows/ci.yml
[npm-image]: https://img.shields.io/npm/v/@quentinadam/secp256k1.svg?style=flat-square
[npm-url]: https://npmjs.org/package/@quentinadam/secp256k1
[jsr-image]: https://jsr.io/badges/@quentinadam/secp256k1?style=flat-square
[jsr-url]: https://jsr.io/@quentinadam/secp256k1
