using System;
using System.IO;

namespace KybusEnigma.Lib.Hashing.MessageDigest
{
    public sealed class Md5 : MessageDigestBase
    {
        public override string Name => "MD5";

        public override int HashLength => 128;

        public override byte[] Hash(byte[] data)
        {
            var paddedInput = PadMd5(data);
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

            var amountOfBlocks = arr.Length / 16;

            var block = new uint[16];
            for (var n = 0; n < amountOfBlocks; n++)
            {
                Array.Copy(arr, 16 * n, block, 0, block.Length);

                var a = hash[0];
                var b = hash[1];
                var c = hash[2];
                var d = hash[3];

                for (var i = 0; i < 64; i++)
                {
                    uint f;
                    int g;

                    if (i < 16)
                    {
                        f = (b & c) | (~b & d);
                        g = i;
                    }
                    else if (i < 32)
                    {
                        f = (d & b) | (~d & c);
                        g = (5 * i + 1) % 16;
                    }
                    else if (i < 48)
                    {
                        f = b ^ c ^ d;
                        g = (3 * i + 5) % 16;
                    }
                    else
                    {
                        f = c ^ (b | ~d);
                        g = (7 * i) % 16;
                    }

                    f += a + K[i] + block[g];
                    a = d;
                    d = c;
                    c = b;
                    b += f.RotL(S[i]);
                }

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
    }
}
