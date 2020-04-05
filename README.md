![Kybus Enigma](docs/logo.svg)

![Kybus.Enigma](https://github.com/dschemp/kybus-enigma/workflows/Kybus.Enigma/badge.svg)

**Kybus Enigma is a cryptographic library project started out of curiosity, fun and for educational reasons.**

The project consists of several algorithms *(see table below)* and corresponding unit tests. *(Benchmarks are planned for later.)*
My plans for the future are to implement many cryptographically relevant algorithms in *(a)symmetric encryption, hashing, message authentication* and some more.

Ideas and (upcoming) implementations are listed in the Issues tab.

## Installation
You can either build the library on your own or use the NuGet package.

#### ... through NuGet:
- Search in the NuGet Package Manager: `KybusEnigma` / [Link](https://www.nuget.org/packages/KybusEnigma)
- Package Manager: `Install-Package KybusEnigma -Version 0.1.0`
- dotnet CLI: `dotnet add package KybusEnigma`

## Notice
This is a purely private hobby so I would not bet my ass on using this for anything serious without testing it extensively *(the unit test ensure that these test case work as intended but special cases can always break my implementation)*!
Because it's a hobby there is no schedule on when I do something or not.

## Available Cryptographic Features:

| Category   | Subcategory              | Type          | Stream Support | Additional Features    |
|------------|--------------------------|---------------|----------------|------------------------|
| Encryption | Symmetric                | AES           |   Planned      | CBC Mode, more planned |
|            | Asymmetric               | RSA           |                |                        |
| Hashing    | Secure Hashing Algorithm | SHA1          |        ✓       |                        |
|            |                          | SHA2          |        ✓       |                        |
|            | Message Digest           | MD4           |        ✓       |                        |
|            |                          | MD5           |        ✓       |                        |
|            | RIPEMD                   | RIPEMD128     |        ✓       |                        |
|            |                          | RIPEMD160     |        ✓       |                        |
| Padding    |                          | ZeroPadding   |   Planned      |                        |
|            |                          | LengthPadding |   Planned      |                        |

**Namespace diagram:** (`*` indicates a class; only accessible classes shown)
```
.
├── Encryption
|   ├── Asymmetric
|   |   ├── Rsa*
|   |   └── AsymmetricKeyPair*
|   ├── Symmetric
|   |    └── Aes*
|   └── EncryptionBase* (abstract, base class)
├── Hashing
|   ├── MessageDigest
|   |   ├── Md4*
|   |   ├── Md5*
|   |   ├── Md6*
|   |   └── MessageDigestBase* (abstract; base class)
|   ├── RipeMd
|   |   ├── RipeMd128*
|   |   ├── RipeMd128*
|   |   └── RipeMdBase* (abstract; base class)
|   ├── SecureHashingAlgorithm
|   |   ├── Sha1
|   |   |   └── Sha1*
|   |   └── Sha2
|   |       ├── Sha224*
|   |       ├── Sha256*
|   |       ├── Sha384*
|   |       ├── Sha512*
|   |       └── Sha2Base* (abstract; base class)
|   └── Hasher* (abstract; base class)
└── Padding
    ├── ZeroPadding*
    └── LengthPadding*
```
