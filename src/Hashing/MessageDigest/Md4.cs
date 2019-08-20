using KybusEnigma.Padding;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KybusEnigma.Hashing.MessageDigest
{
    public sealed class Md4 : MessageDigestBase
    {
        public override string Name => "MD4";

        public override int HashLength => 128;

        public override byte[] Hash(byte[] data)
        {
            var paddedInput = LengthPadding.PadToBlockSize(data, 64, 8, true);
            // Convert bytes to uint array for processing
            var arr = paddedInput.BytesArr2UIntArrLittleEndian();

            // Initial Hash values
            uint[] hash =
            {
                //0x01_23_45_67,  //A
                //0x89_ab_cd_ef,  //B
                //0xfe_dc_ba_98,  //C
                //0x76_54_32_10,  //D
                0x67_45_23_01,  //A
                0xef_cd_ab_89,  //B
                0x98_ba_dc_fe,  //C
                0x10_32_54_76   //D
            };

            // amount of blocks
            var amountOfBlocks = arr.Length / 16;

            var block = new uint[16]; // Message Block
            for (var n = 0; n < amountOfBlocks; n++)
            {
                // Copy data into current message block
                Array.Copy(arr, 16 * n, block, 0, block.Length);

                // 1. Initialize the working variables:
                var a = hash[0];
                var b = hash[1];
                var c = hash[2];
                var d = hash[3];

                // 2. Perform the main hash computation:
                /* Round 1 */
                FF(ref a, b, c, d, block[0],   3); /* 1 */
                FF(ref d, a, b, c, block[1],   7); /* 2 */
                FF(ref c, d, a, b, block[2],  11); /* 3 */
                FF(ref b, c, d, a, block[3],  19); /* 4 */
                FF(ref a, b, c, d, block[4],   3); /* 5 */
                FF(ref d, a, b, c, block[5],   7); /* 6 */
                FF(ref c, d, a, b, block[6],  11); /* 7 */
                FF(ref b, c, d, a, block[7],  19); /* 8 */
                FF(ref a, b, c, d, block[8],   3); /* 9 */
                FF(ref d, a, b, c, block[9],   7); /* 10 */
                FF(ref c, d, a, b, block[10], 11); /* 11 */
                FF(ref b, c, d, a, block[11], 19); /* 12 */
                FF(ref a, b, c, d, block[12],  3); /* 13 */
                FF(ref d, a, b, c, block[13],  7); /* 14 */
                FF(ref c, d, a, b, block[14], 11); /* 15 */
                FF(ref b, c, d, a, block[15], 19); /* 16 */

                /* Round 2 */
                GG(ref a, b, c, d, block[0],   3); /* 17 */
                GG(ref d, a, b, c, block[4],   5); /* 18 */
                GG(ref c, d, a, b, block[8],   9); /* 19 */
                GG(ref b, c, d, a, block[12], 13); /* 20 */
                GG(ref a, b, c, d, block[1],   3); /* 21 */
                GG(ref d, a, b, c, block[5],   5); /* 22 */
                GG(ref c, d, a, b, block[9],   9); /* 23 */
                GG(ref b, c, d, a, block[13], 13); /* 24 */
                GG(ref a, b, c, d, block[2],   3); /* 25 */
                GG(ref d, a, b, c, block[6],   5); /* 26 */
                GG(ref c, d, a, b, block[10],  9); /* 27 */
                GG(ref b, c, d, a, block[14], 13); /* 28 */
                GG(ref a, b, c, d, block[3],   3); /* 29 */
                GG(ref d, a, b, c, block[7],   5); /* 30 */
                GG(ref c, d, a, b, block[11],  9); /* 31 */
                GG(ref b, c, d, a, block[15], 13); /* 32 */

                /* Round 3 */
                HH(ref a, b, c, d, block[0],   3); /* 33 */
                HH(ref d, a, b, c, block[8],   9); /* 34 */
                HH(ref c, d, a, b, block[4],  11); /* 35 */
                HH(ref b, c, d, a, block[12], 15); /* 36 */
                HH(ref a, b, c, d, block[2],   3); /* 37 */
                HH(ref d, a, b, c, block[10],  9); /* 38 */
                HH(ref c, d, a, b, block[6],  11); /* 39 */
                HH(ref b, c, d, a, block[14], 15); /* 40 */
                HH(ref a, b, c, d, block[1],   3); /* 41 */
                HH(ref d, a, b, c, block[9],   9); /* 42 */
                HH(ref c, d, a, b, block[5],  11); /* 43 */
                HH(ref b, c, d, a, block[13], 15); /* 44 */
                HH(ref a, b, c, d, block[3],   3); /* 45 */
                HH(ref d, a, b, c, block[11],  9); /* 46 */
                HH(ref c, d, a, b, block[7],  11); /* 47 */
                HH(ref b, c, d, a, block[15], 15); /* 48 */

                // 3. Compute the intermediate hash value H(i)
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
            }

            return hash.UIntsArr2BytesArrLittleEndian();
        }

        public override byte[] Hash(Stream stream)
        {
            throw new NotImplementedException();
        }

        #region Functions

        private void FF(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            a += ((b & c) | (~b & d)) + x;
            a = a.RotL(s);
        }

        private void GG(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            a += ((b & c) | (b & d) | (c & d)) + x + 0x5a827999u;
            a = a.RotL(s);
        }

        private void HH(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            a += (b ^ c ^ d) + x + 0x6ed9eba1u;
            a = a.RotL(s);
        }

        #endregion
    }
}
