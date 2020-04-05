using System;
using System.IO;
using System.Linq;
using Kybus.Enigma.Padding;

namespace Kybus.Enigma.Hashing.SecureHashingAlgorithm.Sha2
{
    public sealed class Sha224 : Sha2Base
    {
        public override string Name => "SHA2-224";

        public override int HashLength => 224;

        public override byte[] Hash(byte[] data)
        {
            byte[] paddedInput = LengthPadding.PadToBlockSize(data, 64, 8);

            // Convert input byte array to uint array for processing
            uint[] arr = paddedInput.UInt8ArrToUInt32Arr();

            // Initial Values
            uint[] hash =
            {
                0xc1059ed8,
                0x367cd507,
                0x3070dd17,
                0xf70e5939,
                0xffc00b31,
                0x68581511,
                0x64f98fa7,
                0xbefa4fa4
            };

            // amount of blocks
            int n = arr.Length / 16;

            uint[] m = new uint[16]; // M_0 -> M_15, Current Block
            uint[] w = new uint[64]; // W_0 -> W_63, Message Schedule

            // Process each block
            for (int i = 0; i < n; i++)
            {
                // Copy data into current message block
                Array.Copy(arr, i * m.Length, m, 0, m.Length);

                // 1. Prepare the message schedule W:
                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (int t in Enumerable.Range(16, 48))
                {
                    w[t] = SmallSigma1(w[t - 2]) + w[t - 7] + SmallSigma0(w[t - 15]) + w[t - 16];
                }

                // 2. Initialize the working variables:
                uint a = hash[0];
                uint b = hash[1];
                uint c = hash[2];
                uint d = hash[3];
                uint e = hash[4];
                uint f = hash[5];
                uint g = hash[6];
                uint h = hash[7];

                // 3. Perform the main hash computation:
                foreach (int t in Enumerable.Range(0, 64))
                {
                    uint t1 = h + BigSigma1(e) + Ch(e, f, g) + _k256[t] + w[t];
                    uint t2 = BigSigma0(a) + Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                // 4. Compute the intermediate hash value H(i)
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
                hash[4] += e;
                hash[5] += f;
                hash[6] += g;
                hash[7] += h;
            }

            uint[] output = { hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6] };

            return output.UInt32ArrToUInt8Arr();
        }

        public override byte[] Hash(Stream stream)
        {
            if (!stream.CanRead)
            {
                throw new IOException("Cannot read stream.");
            }

            // Initial Values
            uint[] hash =
            {
                0xc1059ed8,
                0x367cd507,
                0x3070dd17,
                0xf70e5939,
                0xffc00b31,
                0x68581511,
                0x64f98fa7,
                0xbefa4fa4
            };

            uint[] w = new uint[64]; // W_0 -> W_63, Message Schedule

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

                // 1. Prepare the message schedule W:
                Array.Copy(m, 0, w, 0, m.Length);
                foreach (int t in Enumerable.Range(16, 48))
                {
                    w[t] = SmallSigma1(w[t - 2]) + w[t - 7] + SmallSigma0(w[t - 15]) + w[t - 16];
                }

                // 2. Initialize the working variables:
                uint a = hash[0];
                uint b = hash[1];
                uint c = hash[2];
                uint d = hash[3];
                uint e = hash[4];
                uint f = hash[5];
                uint g = hash[6];
                uint h = hash[7];

                // 3. Perform the main hash computation:
                foreach (int t in Enumerable.Range(0, 64))
                {
                    uint t1 = h + BigSigma1(e) + Ch(e, f, g) + _k256[t] + w[t];
                    uint t2 = BigSigma0(a) + Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                // 4. Compute the intermediate hash value H(i)
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
                hash[4] += e;
                hash[5] += f;
                hash[6] += g;
                hash[7] += h;
            }

            uint[] output = { hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6] };
            return output.UInt32ArrToUInt8Arr();
        }
    }
}
