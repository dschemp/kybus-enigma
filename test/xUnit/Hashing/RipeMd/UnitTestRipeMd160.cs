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
    public class UnitTestRipeMd160
    {
        /*
         * Test Vectors from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
         */

        #region Global Variables

        public Hasher RipeMd160;
        public TestVectorContainer<string, byte[], string, byte[]> TestVectors;
        public TestVectorContainer<string, Stream, string, byte[]> TestVectorsStream;

        #endregion

        #region Setup / Initialiazation

        public UnitTestRipeMd160()
        {
            RipeMd160 = new RipeMd160();

            var oneMillionAs = new string('a', (int)1e6);

            TestVectors = new TestVectorContainer<string, byte[], string, byte[]>(Converter.Text2Bytes, Converter.HexByteDecode)
            {
                { ""                                                                                , "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
                { "a"                                                                               , "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
                { "abc"                                                                             , "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
                { "message digest"                                                                  , "5d0689ef49d2fae572b881b123a85ffa21595f36"},
                { "abcdefghijklmnopqrstuvwxyz"                                                      , "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
                { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"                        , "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
                { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"                  , "b0e20b6e3116640286ed3a87a5713079b21f5189"},
                { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9b752e45573d4b39f4dbd3323cab82bf63326bfb"},
                { oneMillionAs                                                                      , "52783243c1697bdbe16d37f97f68f08325dc1528"}
            };

            TestVectorsStream = new TestVectorContainer<string, Stream, string, byte[]>(Converter.GenerateStreamFromString, Converter.HexByteDecode)
            {
                { ""                                                                                , "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
                { "a"                                                                               , "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
                { "abc"                                                                             , "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
                { "message digest"                                                                  , "5d0689ef49d2fae572b881b123a85ffa21595f36"},
                { "abcdefghijklmnopqrstuvwxyz"                                                      , "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
                { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"                        , "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
                { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"                  , "b0e20b6e3116640286ed3a87a5713079b21f5189"},
                { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9b752e45573d4b39f4dbd3323cab82bf63326bfb"},
                { oneMillionAs                                                                      , "52783243c1697bdbe16d37f97f68f08325dc1528"}
            };

        }

        #endregion

        #region RIPEMD-160

        [Fact(DisplayName = "RIPEMD-160: Empty String")]
        public void RipeMd160_EmptyString()
        {
            var (data, expected) = TestVectors[0];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160: \"a\"")]
        public void RipeMd160_a()
        {
            var (data, expected) = TestVectors[1];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160: \"abc\"")]
        public void RipeMd160_abc()
        {
            var (data, expected) = TestVectors[2];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160: \"message digest\"")]
        public void RipeMd160_messagedigest()
        {
            var (data, expected) = TestVectors[3];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160: \"abcdefghijklmnopqrstuvwxyz\"")]
        public void RipeMd160_a2z()
        {
            var (data, expected) = TestVectors[4];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160: \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"")]
        public void RipeMd160_RepeatingLetters()
        {
            var (data, expected) = TestVectors[5];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160: \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\"")]
        public void RipeMd160_a2zA2Z029()
        {
            var (data, expected) = TestVectors[6];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160: \"12345678901234567890123456789012345678901234567890123456789012345678901234567890\"")]
        public void RipeMd160_eightTimesFrom0to9()
        {
            var (data, expected) = TestVectors[7];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160: One Million a's")]
        public void RipeMd160_OneMillionSmallAs()
        {
            var (data, expected) = TestVectors[8];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion

        #region RIPEMD-160-Stream

        [Fact(DisplayName = "RIPEMD-160-Stream: Empty String")]
        public void RipeMd160Stream_EmptyString()
        {
            var (data, expected) = TestVectorsStream[0];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160-Stream: \"a\"")]
        public void RipeMd160Stream_a()
        {
            var (data, expected) = TestVectorsStream[1];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160-Stream: \"abc\"")]
        public void RipeMd160Stream_abc()
        {
            var (data, expected) = TestVectorsStream[2];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160-Stream: \"message digest\"")]
        public void RipeMd160Stream_messagedigest()
        {
            var (data, expected) = TestVectorsStream[3];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160-Stream: \"abcdefghijklmnopqrstuvwxyz\"")]
        public void RipeMd160Stream_a2z()
        {
            var (data, expected) = TestVectorsStream[4];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160-Stream: \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"")]
        public void RipeMd160Stream_RepeatingLetters()
        {
            var (data, expected) = TestVectorsStream[5];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160-Stream: \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\"")]
        public void RipeMd160Stream_a2zA2Z029()
        {
            var (data, expected) = TestVectorsStream[6];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160-Stream: \"12345678901234567890123456789012345678901234567890123456789012345678901234567890\"")]
        public void RipeMd160Stream_eightTimesFrom0to9()
        {
            var (data, expected) = TestVectorsStream[7];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        [Fact(DisplayName = "RIPEMD-160-Stream: One Million a's")]
        public void RipeMd160Stream_OneMillionSmallAs()
        {
            var (data, expected) = TestVectorsStream[8];

            var hash = RipeMd160.Hash(data);
            CustomAssert.MatchArrays(hash, expected);
        }

        #endregion
    }
}
