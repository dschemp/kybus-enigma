using KybusEnigma.Lib.Hashing.MessageDigest;
using KybusEnigma.xUnit.Helper;
using Xunit;

namespace KybusEnigma.xUnit.Hashing.MessageDigest
{
    public class UnitTestMd5
    {
        /*
         * https://tools.ietf.org/html/rfc1321
         */

        #region Global Variables

        public Md5 Md5;
        public TestVectorContainer<string, byte[], string, byte[]> TestVectors;

        #endregion

        #region Setup / Initialization

        public UnitTestMd5()
        {
            Md5 = new Md5();
            TestVectors = new TestVectorContainer<string, byte[], string, byte[]>(Converter.Text2Bytes, Converter.HexByteDecode)
            {
                {"Quick Brown Fox", "The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"},
                {"Empty String"   , "", "d41d8cd98f00b204e9800998ecf8427e"},
                {"a" , "a", "0cc175b9c0f1b6a831c399e269772661"},
                {"abc" , "abc", "900150983cd24fb0d6963f7d28e17f72"},
                {"message digest" , "message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
                {"a-z" , "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
                {"A-Za-z0-9" , "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
                {"LargeNumber" , "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"},
            };
        }

            #endregion

        #region Md5

        [Fact(DisplayName = "MD5: \"The quick brown fox jumps over the lazy dog\"")]
        public void Md5_QuickBrownFox()
        {
            var (data, expected) = TestVectors["Quick Brown Fox"];

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD5: Empty String")]
        public void Md5_EmptyString()
        {
            var (data, expected) = TestVectors["Empty String"];

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD5: \"a\"")]
        public void Md5_SingleSmallA()
        {
            var (data, expected) = TestVectors["a"];

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD5: \"abc\"")]
        public void Md5_abc()
        {
            var (data, expected) = TestVectors["abc"];

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD5: \"message digest\"")]
        public void Md5_MessageDigest()
        {
            var (data, expected) = TestVectors["message digest"];

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD5: \"a-z\"")]
        public void Md5_a2z()
        {
            var (data, expected) = TestVectors["a-z"];

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD5: \"A-Za-z0-9\"")]
        public void Md5_A2Za2z029()
        {
            var (data, expected) = TestVectors["A-Za-z0-9"];

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD5: \"LargeNumber\"")]
        public void Md5_LargeNumber()
        {
            var (data, expected) = TestVectors["LargeNumber"];

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion
    }
}