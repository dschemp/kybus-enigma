using KybusEnigma.Hashing;
using KybusEnigma.Hashing.RipeMd;
using KybusEnigma.xUnit.Helper;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Xunit;

namespace KybusEnigma.xUnit.Hashing.RipeMd
{
    public class UnitTestRipeMd128
    {
        /*
         * Test Vectors from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
         */

        #region Global Variables

        public Hasher RipeMd128;
        public TestVectorContainer<string, byte[], string, byte[]> TestVectors;
        public TestVectorContainer<string, Stream, string, byte[]> TestVectorsStream;

        #endregion

        #region Setup / Initialiazation

        public UnitTestRipeMd128()
        {
            RipeMd128 = new RipeMd128();

            var oneMillionAs = new string('a', (int)1e6);

            TestVectors = new TestVectorContainer<string, byte[], string, byte[]>(Converter.Text2Bytes, Converter.HexByteDecode)
            {
                { ""                                                                                , "cdf26213a150dc3ecb610f18f6b38b46"},
                { "a"                                                                               , "86be7afa339d0fc7cfc785e72f578d33"},
                { "abc"                                                                             , "c14a12199c66e4ba84636b0f69144c77"},
                { "message digest"                                                                  , "9e327b3d6e523062afc1132d7df9d1b8"},
                { "abcdefghijklmnopqrstuvwxyz"                                                      , "fd2aa607f71dc8f510714922b371834e"},
                { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"                        , "a1aa0689d0fafa2ddc22e88b49133a06"},
                { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"                  , "d1e959eb179c911faea4624c60c5c702"},
                { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "3f45ef194732c2dbb2c4a2c769795fa3"},
                { oneMillionAs                                                                      , "4a7f5723f954eba1216c9d8f6320431f"}
            };

            TestVectorsStream = new TestVectorContainer<string, Stream, string, byte[]>(Converter.GenerateStreamFromString, Converter.HexByteDecode)
            {
                { ""                                                                                , "cdf26213a150dc3ecb610f18f6b38b46"},
                { "a"                                                                               , "86be7afa339d0fc7cfc785e72f578d33"},
                { "abc"                                                                             , "c14a12199c66e4ba84636b0f69144c77"},
                { "message digest"                                                                  , "9e327b3d6e523062afc1132d7df9d1b8"},
                { "abcdefghijklmnopqrstuvwxyz"                                                      , "fd2aa607f71dc8f510714922b371834e"},
                { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"                        , "a1aa0689d0fafa2ddc22e88b49133a06"},
                { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"                  , "d1e959eb179c911faea4624c60c5c702"},
                { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "3f45ef194732c2dbb2c4a2c769795fa3"},
                { oneMillionAs                                                                      , "4a7f5723f954eba1216c9d8f6320431f"}
            };

        }

        #endregion

        #region RIPEMD-128

        [Fact(DisplayName = "RIPEMD-128: Empty String")]
        public void RipeMd128_EmptyString()
        {
            var (data, expected) = TestVectors[0];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128: \"a\"")]
        public void RipeMd128_a()
        {
            var (data, expected) = TestVectors[1];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128: \"abc\"")]
        public void RipeMd128_abc()
        {
            var (data, expected) = TestVectors[2];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128: \"message digest\"")]
        public void RipeMd128_messagedigest()
        {
            var (data, expected) = TestVectors[3];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128: \"abcdefghijklmnopqrstuvwxyz\"")]
        public void RipeMd128_a2z()
        {
            var (data, expected) = TestVectors[4];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128: \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"")]
        public void RipeMd128_RepeatingLetters()
        {
            var (data, expected) = TestVectors[5];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128: \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\"")]
        public void RipeMd128_a2zA2Z029()
        {
            var (data, expected) = TestVectors[6];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128: \"12345678901234567890123456789012345678901234567890123456789012345678901234567890\"")]
        public void RipeMd128_eightTimesFrom0to9()
        {
            var (data, expected) = TestVectors[7];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128: One Million a's")]
        public void RipeMd128_OneMillionSmallAs()
        {
            var (data, expected) = TestVectors[8];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion

        #region RIPEMD-128-Stream

        [Fact(DisplayName = "RIPEMD-128-Stream: Empty String")]
        public void RipeMd128Stream_EmptyString()
        {
            var (data, expected) = TestVectorsStream[0];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128-Stream: \"a\"")]
        public void RipeMd128Stream_a()
        {
            var (data, expected) = TestVectorsStream[1];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128-Stream: \"abc\"")]
        public void RipeMd128Stream_abc()
        {
            var (data, expected) = TestVectorsStream[2];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128-Stream: \"message digest\"")]
        public void RipeMd128Stream_messagedigest()
        {
            var (data, expected) = TestVectorsStream[3];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128-Stream: \"abcdefghijklmnopqrstuvwxyz\"")]
        public void RipeMd128Stream_a2z()
        {
            var (data, expected) = TestVectorsStream[4];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128-Stream: \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"")]
        public void RipeMd128Stream_RepeatingLetters()
        {
            var (data, expected) = TestVectorsStream[5];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128-Stream: \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\"")]
        public void RipeMd128Stream_a2zA2Z029()
        {
            var (data, expected) = TestVectorsStream[6];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128-Stream: \"12345678901234567890123456789012345678901234567890123456789012345678901234567890\"")]
        public void RipeMd128Stream_eightTimesFrom0to9()
        {
            var (data, expected) = TestVectorsStream[7];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-128-Stream: One Million a's")]
        public void RipeMd128Stream_OneMillionSmallAs()
        {
            var (data, expected) = TestVectorsStream[8];

            var hash = RipeMd128.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion
    }
}
