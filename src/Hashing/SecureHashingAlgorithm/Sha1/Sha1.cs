using System;
using System.IO;
using System.Linq;
using Kybus.Enigma.Padding;

namespace Kybus.Enigma.Hashing.SecureHashingAlgorithm.Sha1
{
    public class Sha1 : Hasher
    {
        public override string Name => "SHA-1";

        public override int HashLength => 160;

        public override byte[] Hash(byte[] data)
        {
            byte[] paddedInput = LengthPadding.PadToBlockSize(data, 64, 8);

            // Convert input byte array to uint array for processing
            uint[] arr = paddedInput.UInt8ArrToUInt32Arr();

            // Initial values
            uint[] hash =
            {
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
            };

            // amount of blocks
            int amountOfBlocks = arr.Length / 16;

            uint[] m = new uint[16]; // M_0 -> M_15, Message Block
            uint[] w = new uint[80]; // W_0 -> W_79, Message Schedule

            // Process each block
            for (int n = 0; n < amountOfBlocks; n++)
            {
                // Copy data into current message block
                Array.Copy(arr, n * m.Length, m, 0, m.Length);

                // 1. Prepare the message schedule W:
                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (int t in Enumerable.Range(16, 64))
                {
                    w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).RotL(1);
                }

                // 2. Initialize the working variables:
                uint a = hash[0];
                uint b = hash[1];
                uint c = hash[2];
                uint d = hash[3];
                uint e = hash[4];

                // 3. Perform the main hash computation:
                foreach (int t in Enumerable.Range(0, 80))
                {
                    uint temp = a.RotL(5) + F(t, b, c, d) + e + w[t] + K(t);
                    e = d;
                    d = c;
                    c = b.RotL(30);
                    b = a;
                    a = temp;
                }

                // 4. Compute the intermediate hash value H(i)
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
                hash[4] += e;
            }

            return hash.UInt32ArrToUInt8Arr();
        }

        public override byte[] Hash(Stream stream)
        {
            if (!stream.CanRead)
            {
                throw new IOException("Cannot read stream.");
            }

            // Initial values
            uint[] hash =
            {
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
            };

            uint[] w = new uint[80]; // W_0 -> W_79, Message Schedule

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
                    AppendLength(buffer, stream.Length);
                    lengthAppended = true; // ... and mark this block as the last
                }

                uint[] m = buffer.UInt8ArrToUInt32Arr(); // M_0 -> M_15, Current Block

                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (int t in Enumerable.Range(16, 64))
                {
                    w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).RotL(1);
                }

                // 2. Initialize the working variables:
                uint a = hash[0];
                uint b = hash[1];
                uint c = hash[2];
                uint d = hash[3];
                uint e = hash[4];

                // 3. Perform the main hash computation:
                foreach (int t in Enumerable.Range(0, 80))
                {
                    uint temp = a.RotL(5) + F(t, b, c, d) + e + w[t] + K(t);
                    e = d;
                    d = c;
                    c = b.RotL(30);
                    b = a;
                    a = temp;
                }

                // 4. Compute the intermediate hash value H(i)
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
                hash[4] += e;
            }

            return hash.UInt32ArrToUInt8Arr();
        }

        #region Helpers, Functions and Constants

        protected uint F(int t, uint b, uint c, uint d)
        {
            if (t < 20)
            {
                return (b & c) | (~b & d);
            }

            if (t < 40)
            {
                return b ^ c ^ d;
            }

            if (t < 60)
            {
                return (b & c) | (b & d) | (c & d);
            }

            return b ^ c ^ d;
        }

        protected uint K(int t)
        {
            if (t < 20)
            {
                return 0x5A827999;
            }

            if (t < 40)
            {
                return 0x6ED9EBA1;
            }

            if (t < 60)
            {
                return 0x8F1BBCDC;
            }

            return 0xCA62C1D6;
        }

        #endregion
    }
}
