using System;
using KybusEnigma.Lib.Hashing;
using KybusEnigma.Lib.Hashing.Sha2;
using KybusEnigma.XUnit.Helper;
using Xunit;

namespace KybusEnigma.XUnit
{
    public class UnitTestSha2
    {
        /*
         * Test from https://www.di-mgt.com.au/sha_testvectors.html
         */

        private readonly Hasher _sha224, _sha256, _sha384, _sha512;

        public UnitTestSha2()
        {
            _sha224 = new Sha224();
            _sha256 = new Sha256();
            _sha384 = new Sha384();
            _sha512 = new Sha512();

            // TODO: Init test data here as it effects duration of unit tests
        }

        byte[] String2Bytes(string msg) => System.Text.Encoding.UTF8.GetBytes(msg);

        #region Sha224

        [Fact(DisplayName = "Sha-224: \"abc\"")]
        void Sha224_abc()
        {
            var data = String2Bytes("abc");
            var expected = HexBin.Decode("23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7");

            var hash = _sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-224: Empty String")]
        void Sha224_EmptyString()
        {
            var data = String2Bytes("");
            var expected = HexBin.Decode("d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f");

            var hash = _sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-224: 448 Bits")]
        void Sha224_448Bits()
        {
            var data = String2Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            var expected = HexBin.Decode("75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525");

            var hash = _sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-224: 896 Bits")]
        void Sha224_896Bits()
        {
            var data = String2Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
            var expected = HexBin.Decode("c97ca9a5 59850ce9 7a04a96d ef6d99a9 e0e0e2ab 14e6b8df 265fc0b3");

            var hash = _sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-224: One Million times 'a'")]
        void Sha224_OneMillionSmallAs()
        {
            var data = String2Bytes(new string('a', 1_000_000));
            var expected = HexBin.Decode("20794655 980c91d8 bbb4c1ea 97618a4b f03f4258 1948b2ee 4ee7ad67");

            var hash = _sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion

        #region Sha256

        [Fact(DisplayName = "Sha-256: \"abc\"")]
        void Sha256_abc()
        {
            var data = String2Bytes("abc");
            var expected = HexBin.Decode("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad");

            var hash = _sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-256: Empty String")]
        void Sha256_EmptyString()
        {
            var data = String2Bytes("");
            var expected = HexBin.Decode("e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855");

            var hash = _sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-256: 448 Bits")]
        void Sha256_448Bits()
        {
            var data = String2Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            var expected = HexBin.Decode("248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1");

            var hash = _sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-256: 896 Bits")]
        void Sha256_896Bits()
        {
            var data = String2Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
            var expected = HexBin.Decode("cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1");

            var hash = _sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-256: One Million times 'a'")]
        void Sha256_OneMillionSmallAs()
        {
            var data = String2Bytes(new string('a', 1_000_000));
            var expected = HexBin.Decode("cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0");

            var hash = _sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion

        #region Sha384

        [Fact(DisplayName = "Sha-384: \"abc\"")]
        void Sha384_abc()
        {
            var data = String2Bytes("abc");
            var expected = HexBin.Decode("cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7");

            var hash = _sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-384: Empty String")]
        void Sha384_EmptyString()
        {
            var data = String2Bytes("");
            var expected = HexBin.Decode("38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b");

            var hash = _sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-384: 448 Bits")]
        void Sha384_448Bits()
        {
            var data = String2Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            var expected = HexBin.Decode("3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b");

            var hash = _sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-384: 896 Bits")]
        void Sha384_896Bits()
        {
            var data = String2Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
            var expected = HexBin.Decode("09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039");

            var hash = _sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-384: One Million times 'a'")]
        void Sha384_OneMillionSmallAs()
        {
            var data = String2Bytes(new string('a', 1_000_000));
            var expected = HexBin.Decode("9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985");

            var hash = _sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion

        #region Sha512

        [Fact(DisplayName = "Sha-512: \"abc\"")]
        void Sha512_abc()
        {
            var data = String2Bytes("abc");
            var expected = HexBin.Decode("ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f");

            var hash = _sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-512: Empty String")]
        void Sha512_EmptyString()
        {
            var data = String2Bytes("");
            var expected = HexBin.Decode("cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e");

            var hash = _sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-512: 448 Bits")]
        void Sha512_448Bits()
        {
            var data = String2Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            var expected = HexBin.Decode("204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445");

            var hash = _sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-512: 896 Bits")]
        void Sha512_896Bits()
        {
            var data = String2Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
            var expected = HexBin.Decode("8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909");

            var hash = _sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "Sha-512: One Million times 'a'")]
        void Sha512_OneMillionSmallAs()
        {
            var data = String2Bytes(new string('a', 1_000_000));
            var expected = HexBin.Decode("e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b");

            var hash = _sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion
    }
}
