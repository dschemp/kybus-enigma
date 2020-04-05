using System;
using System.IO;
using System.Linq;
using Kybus.Enigma.Padding;

namespace Kybus.Enigma.Hashing.MessageDigest
{
    public sealed class Md5 : MessageDigestBase
    {
        public override string Name => "MD5";

        public override int HashLength => 128;

        public override byte[] Hash(byte[] data)
        {
            byte[] paddedInput = LengthPadding.PadToBlockSize(data, 64, 8, true);

            // Convert bytes to uint array for processing
            uint[] arr = paddedInput.UInt8ArrToUInt32ArrLE();

            // Initial Hash values
            uint[] hash =
            {
                0x67_45_23_01,
                0xef_cd_ab_89,
                0x98_ba_dc_fe,
                0x10_32_54_76
            };

            // amount of blocks
            int amountOfBlocks = arr.Length / 16;

            uint[] block = new uint[16]; // Message Block
            for (int n = 0; n < amountOfBlocks; n++)
            {
                // Copy data into current message block
                Array.Copy(arr, 16 * n, block, 0, block.Length);

                // 1. Initialize the working variables:
                uint a = hash[0];
                uint b = hash[1];
                uint c = hash[2];
                uint d = hash[3];

                // 2. Perform the main hash computation:
                foreach (int i in Enumerable.Range(0, 64))
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
                        g = ((5 * i) + 1) % 16;
                    }
                    else if (i < 48)
                    {
                        f = b ^ c ^ d;
                        g = ((3 * i) + 5) % 16;
                    }
                    else
                    {
                        f = c ^ (b | ~d);
                        g = (7 * i) % 16;
                    }

                    f += a + _k[i] + block[g];
                    a = d;
                    d = c;
                    c = b;
                    b += f.RotL(_sMd5[i]);
                }

                // 3. Compute the intermediate hash value H(i)
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
            }

            return hash.UInt32ArrToUInt8ArrLE();
        }

        public override byte[] Hash(Stream stream)
        {
            if (!stream.CanRead)
            {
                throw new IOException("Cannot read stream.");
            }

            // Initial Hash values
            uint[] hash =
            {
                0x67_45_23_01,
                0xef_cd_ab_89,
                0x98_ba_dc_fe,
                0x10_32_54_76
            };

            uint[] block = new uint[16]; // Message Block

            bool lengthAppended = false;
            bool hasBeenPadded = false;
            int readByteCount;

            // Read and compute as long as the final length bytes have not yet been appended
            while (!lengthAppended)
            {
                // Read in current block and pad if necessary
                readByteCount = ReadInBlock(stream, out byte[] buffer);

                // Only add the 0x80 byte when it's not already been added
                if (readByteCount != buffer.Length && !hasBeenPadded)
                {
                    buffer[readByteCount] = 0x80; // Padding byte
                    hasBeenPadded = true;
                }

                // If there is room for the length bytes, append them ...
                // (including the padding byte in the case of the padding consists of only the padding byte)
                if (readByteCount <= 48)
                {
                    AppendLength(buffer, stream.Length, littleEndian: true);
                    lengthAppended = true; // ... and mark this block as the last
                }

                uint[] m = buffer.UInt8ArrToUInt32ArrLE(); // M_0 -> M_15, Current Block

                // Copy data into current message block
                Array.Copy(m, 0, block, 0, block.Length);

                // 1. Initialize the working variables:
                uint a = hash[0];
                uint b = hash[1];
                uint c = hash[2];
                uint d = hash[3];

                // 2. Perform the main hash computation:
                foreach (int i in Enumerable.Range(0, 64))
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
                        g = ((5 * i) + 1) % 16;
                    }
                    else if (i < 48)
                    {
                        f = b ^ c ^ d;
                        g = ((3 * i) + 5) % 16;
                    }
                    else
                    {
                        f = c ^ (b | ~d);
                        g = (7 * i) % 16;
                    }

                    f += a + _k[i] + block[g];
                    a = d;
                    d = c;
                    c = b;
                    b += f.RotL(_sMd5[i]);
                }

                // 3. Compute the intermediate hash value H(i)
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
            }

            return hash.UInt32ArrToUInt8ArrLE();
        }
    }
}
