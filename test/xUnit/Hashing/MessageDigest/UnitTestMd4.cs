using KybusEnigma.Lib.Hashing.MessageDigest;
using KybusEnigma.xUnit.Helper;
using Xunit;

namespace KybusEnigma.xUnit.Hashing.MessageDigest
{
    public class UnitTestMd4
    {
        /*
         * https://tools.ietf.org/html/rfc1320
         */

        #region Global Variables

        public Md4 Md4;
        public TestVectorContainer<string, byte[], string, byte[]> TestVectors;

        #endregion

        #region Setup / Initialization

        public UnitTestMd4()
        {
            Md4 = new Md4();
            TestVectors = new TestVectorContainer<string, byte[], string, byte[]>(Converter.Text2Bytes, Converter.HexByteDecode)
            {
                {"Empty String"   , "", "31d6cfe0d16ae931b73c59d7e0c089c0"},
                {"a"              , "a", "bde52cb31de33e46245e05fbdbd6fb24"},
                {"abc"            , "abc", "a448017aaf21d8525fc10ae87aa6729d"},
                {"message digest" , "message digest", "d9130a8164549fe818874806e1c7014b"},
                {"a-z"            , "abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
                {"A-Za-z0-9"      , "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
                {"LargeNumber"    , "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"},
            };
        }

            #endregion

        #region MD4

        [Fact(DisplayName = "MD4: Empty String")]
        public void Md4_EmptyString()
        {
            var (data, expected) = TestVectors["Empty String"];

            var hash = Md4.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD4: \"a\"")]
        public void Md4_SingleSmallA()
        {
            var (data, expected) = TestVectors["a"];

            var hash = Md4.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD4: \"abc\"")]
        public void Md4_abc()
        {
            var (data, expected) = TestVectors["abc"];

            var hash = Md4.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD4: \"message digest\"")]
        public void Md4_MessageDigest()
        {
            var (data, expected) = TestVectors["message digest"];

            var hash = Md4.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD4: \"a-z\"")]
        public void Md4_a2z()
        {
            var (data, expected) = TestVectors["a-z"];

            var hash = Md4.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD4: \"A-Za-z0-9\"")]
        public void Md4_A2Za2z029()
        {
            var (data, expected) = TestVectors["A-Za-z0-9"];

            var hash = Md4.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD4: 8 times \"1234567890\"")]
        public void Md4_LargeNumber()
        {
            var (data, expected) = TestVectors["LargeNumber"];

            var hash = Md4.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion
    }
}