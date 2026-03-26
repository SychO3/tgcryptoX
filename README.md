# TgCryptoX

Fast and Portable Cryptography Extension Library for Pyrogram.

Provides AES-256 encryption/decryption in IGE, CTR, and CBC modes, implemented in Rust with PyO3 bindings.

## Installation

```bash
pip install TgCryptoX
```

## Usage

```python
import tgcrypto
import os

# AES-256-IGE
key = os.urandom(32)
iv = os.urandom(32)
data = os.urandom(64)

encrypted = tgcrypto.ige256_encrypt(data, key, iv)
decrypted = tgcrypto.ige256_decrypt(encrypted, key, iv)

# AES-256-CTR
key = os.urandom(32)
iv = bytearray(os.urandom(16))
state = bytearray(b"\x00")
data = os.urandom(100)

encrypted = tgcrypto.ctr256_encrypt(data, key, iv, state)

# AES-256-CBC
key = os.urandom(32)
iv = bytearray(os.urandom(16))
data = os.urandom(64)

encrypted = tgcrypto.cbc256_encrypt(data, key, iv)
```

## Benchmark

Tested on Apple M-series (aarch64), Python 3.14, with ARMv8 hardware AES enabled.

| Size | Mode | TgCrypto (C) | TgCryptoX (Rust) |
|------|------|-------------|-----------------|
| 16B | IGE Encrypt | 409ns | 418ns |
| 256B | IGE Encrypt | 658ns | 604ns |
| 4KB | IGE Encrypt | 4.7us | 4.8us |
| 64KB | IGE Encrypt | 72.0us | 71.8us |
| 1MB | IGE Encrypt | 1.12ms | 1.11ms |
| 1MB | IGE Decrypt | 1.09ms | 1.09ms |
| 1MB | CBC Encrypt | 1.33ms | 1.34ms |
| 1MB | CBC Decrypt | 171.8us | 162.8us |
| 1MB | CTR | 1.28ms | 1.37ms |

Performance is on par with the original C implementation.

## Why Rust?

| | TgCrypto (C) | TgCryptoX (Rust) |
|---|---|---|
| AES core | T-table lookup, vulnerable to cache-timing side-channel attacks | RustCrypto `aes` crate: auto-detected hardware AES (AES-NI / ARMv8) + constant-time fixsliced software fallback, side-channel resistant |
| Memory safety | Manual `malloc`/`free`, risk of leaks and buffer overflows | Compile-time memory safety guaranteed by Rust's ownership system, no use-after-free or buffer overflows |
| Python bindings | Hand-written Python C API (~244 lines), error-prone | Auto-generated via PyO3 macros (~120 lines), type-safe |
| GIL release | Manual `Py_BEGIN/END_ALLOW_THREADS` | Managed by `py.detach()` |
| Build system | setuptools + C compiler configuration | Single-command build with maturin, no C toolchain needed |
| Cross-platform wheels | Complex cibuildwheel configuration required | Native multi-platform support via maturin |
| Code size | ~900 lines C + ~80 lines setup.py | ~250 lines Rust + ~30 lines TOML |

## Acknowledgements

This project is a Rust rewrite of [TgCrypto](https://github.com/pyrogram/tgcrypto) by [Pyrogram](https://github.com/pyrogram). Thanks to the original project for the API design, test vectors, and inspiration.

## License

LGPL-3.0-or-later
