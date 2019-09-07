using KybusEnigma.Padding;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace KybusEnigma.Hashing.RipeMd
{
    public class RipeMd128 : RipeMdBase
    {
        public override string Name => "RIPEMD-128";

        public override int HashLength => 128;

        public override byte[] Hash(byte[] data)
        {
            var paddedInput = LengthPadding.PadToBlockSize(data, 64, 8, true);
            // Convert bytes to uint array for processing
            var arr = paddedInput.UInt8ArrToUInt32ArrLE();

            // Initial Hash values
            uint[] hash =
            {
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476
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

                var _a = hash[0];
                var _b = hash[1];
                var _c = hash[2];
                var _d = hash[3];

                // 2. Perform the main hash computation:
                foreach (var j in Enumerable.Range(0, 64))
                {
                    var s = S_128[j];
                    var sdash = SDash_128[j];

                    var t = (a + f(j, b, c, d) + block[R_128[j]] + K_128(j)).RotL(s);

                    a = d;
                    d = c;
                    c = b;
                    b = t;

                    t = (_a + f(63 - j, _b, _c, _d) + block[RDash_128[j]] + KDash_128(j)).RotL(sdash);

                    _a = _d;
                    _d = _c;
                    _c = _b;
                    _b = t;
                }

                // 3. Compute the intermediate hash value H(i)
                var temp = hash[1] + c + _d;
                hash[1] = hash[2] + d + _a;
                hash[2] = hash[3] + a + _b;
                hash[3] = hash[0] + b + _c;
                hash[0] = temp;
            }

            return hash.UInt32ArrToUInt8ArrLE();
        }

        public override byte[] Hash(Stream stream)
        {
            throw new NotImplementedException();
        }
    }
}
