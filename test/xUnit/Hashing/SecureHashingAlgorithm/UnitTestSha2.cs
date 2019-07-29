using KybusEnigma.Lib.Hashing;
using KybusEnigma.Lib.Hashing.SecureHashingAlgorithm.Sha2;
using KybusEnigma.xUnit.Helper;
using Xunit;

namespace KybusEnigma.xUnit.Hashing.SecureHashingAlgorithm
{
    public class UnitTestSha2
    {
        /*
         * Test from https://www.di-mgt.com.au/sha_testvectors.html
         */

        #region Global Variables

        public Hasher Sha224, Sha256, Sha384, Sha512;
        public TestVectorContainer<string, string> TestVectors;

        #endregion

        #region Setup / Initialization

        public UnitTestSha2()
        {
            Sha224 = new Sha224();
            Sha256 = new Sha256();
            Sha384 = new Sha384();
            Sha512 = new Sha512();

            var oneMillionAs = new string('a', (int)1e6);

            TestVectors = new TestVectorContainer<string, string>(Converter.Text2Bytes, Converter.HexByteDecode)
            {
                {"Sha224 abc"           , "abc", "23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7"},
                {"Sha224 Empty String"  , "", "d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f"},
                {"Sha224 448 Bits"      , "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525"},
                {"Sha224 896 Bits"      , "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "c97ca9a5 59850ce9 7a04a96d ef6d99a9 e0e0e2ab 14e6b8df 265fc0b3"},
                {"Sha224 One Million As", oneMillionAs, "20794655 980c91d8 bbb4c1ea 97618a4b f03f4258 1948b2ee 4ee7ad67"},

                {"Sha256 abc"           , "abc", "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad"},
                {"Sha256 Empty String"  , "", "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855"},
                {"Sha256 448 Bits"      , "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1"},
                {"Sha256 896 Bits"      , "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1"},
                {"Sha256 One Million As", oneMillionAs, "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0"},

                {"Sha384 abc"           , "abc", "cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7"},
                {"Sha384 Empty String"  , "", "38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b"},
                {"Sha384 448 Bits"      , "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b"},
                {"Sha384 896 Bits"      , "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039"},
                {"Sha384 One Million As", oneMillionAs, "9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985"},

                {"Sha512 abc"           , "abc", "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f"},
                {"Sha512 Empty String"  , "", "cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e"},
                {"Sha512 448 Bits"      , "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445"},
                {"Sha512 896 Bits"      , "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909"},
                {"Sha512 One Million As", oneMillionAs, "e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b"}
            };
        }

        #endregion

        #region Sha224

        [Fact(DisplayName = "SHA-224: \"abc\"")]
        public void Sha224_abc()
        {
            var (data, expected) = TestVectors.Get("Sha224 abc");

            var hash = Sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-224: Empty String")]
        public void Sha224_EmptyString()
        {
            var (data, expected) = TestVectors.Get("Sha224 Empty String");

            var hash = Sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-224: 448 Bits")]
        public void Sha224_448Bits()
        {
            var (data, expected) = TestVectors.Get("Sha224 448 Bits");

            var hash = Sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-224: 896 Bits")]
        public void Sha224_896Bits()
        {
            var (data, expected) = TestVectors.Get("Sha224 896 Bits");

            var hash = Sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-224: One Million times 'a'")]
        public void Sha224_OneMillionSmallAs()
        {
            var (data, expected) = TestVectors.Get("Sha224 One Million As");

            var hash = Sha224.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion

        #region Sha256

        [Fact(DisplayName = "SHA-256: \"abc\"")]
        public void Sha256_abc()
        {
            var (data, expected) = TestVectors.Get("Sha256 abc");

            var hash = Sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-256: Empty String")]
        public void Sha256_EmptyString()
        {
            var (data, expected) = TestVectors.Get("Sha256 Empty String");

            var hash = Sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-256: 448 Bits")]
        public void Sha256_448Bits()
        {
            var (data, expected) = TestVectors.Get("Sha256 448 Bits");

            var hash = Sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-256: 896 Bits")]
        public void Sha256_896Bits()
        {
            var (data, expected) = TestVectors.Get("Sha256 896 Bits");

            var hash = Sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-256: One Million times 'a'")]
        public void Sha256_OneMillionSmallAs()
        {
            var (data, expected) = TestVectors.Get("Sha256 One Million As");

            var hash = Sha256.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion

        #region Sha384

        [Fact(DisplayName = "SHA-384: \"abc\"")]
        public void Sha384_abc()
        {
            var (data, expected) = TestVectors.Get("Sha384 abc");

            var hash = Sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-384: Empty String")]
        public void Sha384_EmptyString()
        {
            var (data, expected) = TestVectors.Get("Sha384 Empty String");

            var hash = Sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-384: 448 Bits")]
        public void Sha384_448Bits()
        {
            var (data, expected) = TestVectors.Get("Sha384 448 Bits");

            var hash = Sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-384: 896 Bits")]
        public void Sha384_896Bits()
        {
            var (data, expected) = TestVectors.Get("Sha384 896 Bits");

            var hash = Sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-384: One Million times 'a'")]
        public void Sha384_OneMillionSmallAs()
        {
            var (data, expected) = TestVectors.Get("Sha384 One Million As");

            var hash = Sha384.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion

        #region Sha512

        [Fact(DisplayName = "SHA-512: \"abc\"")]
        public void Sha512_abc()
        {
            var (data, expected) = TestVectors.Get("Sha512 abc");

            var hash = Sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-512: Empty String")]
        public void Sha512_EmptyString()
        {
            var (data, expected) = TestVectors.Get("Sha512 Empty String");

            var hash = Sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-512: 448 Bits")]
        public void Sha512_448Bits()
        {
            var (data, expected) = TestVectors.Get("Sha512 448 Bits");

            var hash = Sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-512: 896 Bits")]
        public void Sha512_896Bits()
        {
            var (data, expected) = TestVectors.Get("Sha512 896 Bits");

            var hash = Sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "SHA-512: One Million times 'a'")]
        public void Sha512_OneMillionSmallAs()
        {
            var (data, expected) = TestVectors.Get("Sha512 One Million As");

            var hash = Sha512.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion
    }
}
