using System;
using System.Collections.Generic;
using System.Text;
using KybusEnigma.Lib.Hashing.MessageDigest;
using KybusEnigma.xUnit.Helper;
using Xunit;

namespace KybusEnigma.xUnit
{
    public class UnitTestMd5
    {
        public Md5 Md5;
        public TestVectorContainer<string, string> TestVectors;

        public UnitTestMd5()
        {
            Md5 = new Md5();
            TestVectors = new TestVectorContainer<string, string>(Converter.Text2Bytes, Converter.HexByteDecode)
            {
                {"Quick Brown Fox", "The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"},
                {"Empty String"   , "", "d41d8cd98f00b204e9800998ecf8427e"}
            };
        }

        [Fact(DisplayName = "MD5: \"The quick brown fox jumps over the lazy dog\"")]
        public void Md5_QuickBrownFox()
        {
            var (data, expected) = TestVectors.Get("Quick Brown Fox");

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "MD5: Empty String")]
        public void Md5_EmptyString()
        {
            var (data, expected) = TestVectors.Get("Empty String");

            var hash = Md5.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }
    }
}