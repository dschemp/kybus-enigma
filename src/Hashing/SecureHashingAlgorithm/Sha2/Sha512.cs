using System;
using System.IO;
using System.Linq;
using Kybus.Enigma.Padding;

namespace Kybus.Enigma.Hashing.SecureHashingAlgorithm.Sha2
{
    public sealed class Sha512 : Sha2Base
    {
        public override string Name => "SHA2-512";

        public override int HashLength => 512;

        public override byte[] Hash(byte[] data)
        {
            byte[] paddedInput = LengthPadding.PadToBlockSize(data, 128, 16);

            // Convert input bytes to ulong array
            ulong[] arr = paddedInput.UInt8ArrToUInt64Arr();

            // Initial values
            ulong[] hash =
            {
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179
            };

            // amount of blocks
            int n = arr.Length / 16;

            ulong[] m = new ulong[16]; // M_0 -> M_15, Message Block
            ulong[] w = new ulong[80]; // W_0 -> W_79, Message Schedule

            // Process each block
            for (int i = 0; i < n; i++)
            {
                // message block
                Array.Copy(arr, i * m.Length, m, 0, m.Length);

                // 1. Prepare the message schedule W:
                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (int t in Enumerable.Range(start: 16, count: 64))
                {
                    w[t] = SmallSigma1(w[t - 2]) + w[t - 7] + SmallSigma0(w[t - 15]) + w[t - 16];
                }

                // 2. Initialize the working variables:
                ulong a = hash[0];
                ulong b = hash[1];
                ulong c = hash[2];
                ulong d = hash[3];
                ulong e = hash[4];
                ulong f = hash[5];
                ulong g = hash[6];
                ulong h = hash[7];

                // 3. Perform the main hash computation:
                foreach (int t in Enumerable.Range(0, 80))
                {
                    ulong t1 = h + BigSigma1(e) + Ch(e, f, g) + _k512[t] + w[t];
                    ulong t2 = BigSigma0(a) + Maj(a, b, c);
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

            return hash.UInt64ArrToUInt8Arr();
        }

        public override byte[] Hash(Stream stream)
        {
            if (!stream.CanRead)
            {
                throw new IOException("Cannot read stream.");
            }

            // Initial values
            ulong[] hash =
            {
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179
            };

            ulong[] w = new ulong[80]; // W_0 -> W_79, Message Schedule

            bool lengthAppended = false;
            bool hasBeenPadded = false;
            int readByteCount;

            // Read and compute as long as the final length bytes have not yet been appended
            while (!lengthAppended)
            {
                // Read in current block and pad if necessary
                readByteCount = ReadInBlock(stream, out byte[] buffer, 128);

                // Only add the 0x80 byte when it's not already been added
                if (readByteCount != buffer.Length && !hasBeenPadded)
                {
                    buffer[readByteCount] = 0x80; // Padding byte
                    hasBeenPadded = true;
                }

                // If there is room for the length bytes, append them ...
                // (including the padding byte in the case of the padding consists of only the padding byte)
                if (readByteCount < 112)
                {
                    AppendLength(buffer, stream.Length);
                    lengthAppended = true; // ... and mark this block as the last
                }

                ulong[] m = buffer.UInt8ArrToUInt64Arr(); // M_0 -> M_15, Current Block

                // 1. Prepare the message schedule W:
                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (int t in Enumerable.Range(start: 16, count: 64))
                {
                    w[t] = SmallSigma1(w[t - 2]) + w[t - 7] + SmallSigma0(w[t - 15]) + w[t - 16];
                }

                // 2. Initialize the working variables:
                ulong a = hash[0];
                ulong b = hash[1];
                ulong c = hash[2];
                ulong d = hash[3];
                ulong e = hash[4];
                ulong f = hash[5];
                ulong g = hash[6];
                ulong h = hash[7];

                // 3. Perform the main hash computation:
                foreach (int t in Enumerable.Range(0, 80))
                {
                    ulong t1 = h + BigSigma1(e) + Ch(e, f, g) + _k512[t] + w[t];
                    ulong t2 = BigSigma0(a) + Maj(a, b, c);
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

            return hash.UInt64ArrToUInt8Arr();
        }
    }
}
