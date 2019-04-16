# Andhell.Crypto.NETstandard
NETstandard crypto library
## What is this?
This is a Implementation of Andhell.Crypto, with .NETstandard only. 
**I recommend to use the libsodium version available at [Andhell.Crypto](https://github.com/AndHell/Andhell.Crypto)**


## Features
- [x] Password Hashing
- [x] General Hashing
- [x] Keyed Hashing
- [ ] Password based Key Derivation *not ready*
- [x] Symmetric Encryption and Decryption
    - [ ] Authenticated Encryption *not ready*
- [ ] Asymmetric Encryption and Decryption *not ready*

## Tools and Build
The Solution can be opened with [Visual Studio 2017](https://visualstudio.microsoft.com/vs/) (and later) or [VS Core](https://code.visualstudio.com/). It is based [.NET Standard 2.0](https://docs.microsoft.com/en-us/dotnet/standard/net-standard). The MSTest Unit Tests are based on [.NET Core 2.1](https://docs.microsoft.com/en-us/dotnet/core/)

**Build on Linux:**
```bash
cd andhell.crypto
dotnet build
```

# Documentation
Since this project uses the same interface as [Andhell.Crypto](https://github.com/AndHell/Andhell.Crypto) please use the documentation available there.

# Licenses
- Andhell.Crypto: [LGPG](LICENSE)