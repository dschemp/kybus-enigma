![Kybus Enigma](docs/logo.svg)

**Kybus Enigma is a cryptographic library project started out of curiosity, fun and for educational reasons.**

The project consists of several algorithms *(see table below)* and corresponding unit tests. *(Benchmarks are planned for later.)*
My plans for the future are to implement many cryptographically relevant algorithms in *(a)symmetric encryption, hashing, message authentication* and some more.

Ideas and (upcoming) implementations are listed in the Issues tab.

## Notice
This is a purely private hobby so I would not bet my ass on using this for anything serious without testing it extensively *(the unit test ensure that these test case work as intended but special cases can always break my implementation)*!
Because it's a hobby there is no schedule on when I do something or not.

## Available Cryptographic Features:

| Category   | Subcategory              | Type             | Stream Support | Additional Features |
|------------|--------------------------|------------------|----------------|---------------------|
| Encryption | Symmetric                | AES              |   Planned      | CBC Mode            |
|            | Asymmetric               | RSA              |                |                     |
| Hashing    | Secure Hashing Algorithm | SHA1             |        ✓       |                     |
|            |                          | SHA2             |        ✓       |                     |
|            | Message Digest           | MD4              |   Planned      |                     |
|            |                          | MD5              |   Planned      |                     |
|            | RIPEMD                   | RIPEMD128        |   Planned      |                     |
|            |                          | RIPEMD160        |   Planned      |                     |
| Padding    | -                        | ZeroPadding      |   Planned      |                     |
|            |                          | BlockBytePadding |   Planned      |                     |

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
    └── BlockBytePadding*
```
