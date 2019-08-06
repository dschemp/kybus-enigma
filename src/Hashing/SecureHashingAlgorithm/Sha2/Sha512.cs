using System;
using System.IO;
using System.Linq;

namespace KybusEnigma.Lib.Hashing.SecureHashingAlgorithm.Sha2
{
    public sealed class Sha512 : Sha2Base
    {
        public override byte[] Hash(byte[] data)
        {
            var paddedInput = Pad512(data);
            // Convert input bytes to ulong array
            var arr = paddedInput.BytesArr2ULongArr();

            // Initial values
            ulong[] hash =
            {
                0x6a09e667f3bcc908, // H_0
                0xbb67ae8584caa73b, // H_1
                0x3c6ef372fe94f82b, // H_2
                0xa54ff53a5f1d36f1, // H_3
                0x510e527fade682d1, // H_4
                0x9b05688c2b3e6c1f, // H_5
                0x1f83d9abfb41bd6b, // H_6
                0x5be0cd19137e2179  // H_7
            };

            // amount of blocks
            var n = arr.Length / 16;

            var m = new ulong[16]; // M_0 -> M_15, Message Block
            var w = new ulong[80]; // W_0 -> W_79, Message Schedule

            // Process each block
            for (var i = 0; i < n; i++)
            {
                // message block
                Array.Copy(arr, i * m.Length, m, 0, m.Length);

                // 1. Prepare the message schedule W:
                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (var t in Enumerable.Range(start: 16, count: 64))
                    w[t] = SmallSigma1(w[t - 2]) + w[t - 7] + SmallSigma0(w[t - 15]) + w[t - 16];

                // 2. Initialize the working variables:
                var a = hash[0];
                var b = hash[1];
                var c = hash[2];
                var d = hash[3];
                var e = hash[4];
                var f = hash[5];
                var g = hash[6];
                var h = hash[7];

                // 3. Perform the main hash computation:
                foreach (var t in Enumerable.Range(0, 80))
                {
                    var t1 = h + BigSigma1(e) + Ch(e, f, g) + K512[t] + w[t];
                    var t2 = BigSigma0(a) + Maj(a, b, c);
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

            return hash.ULongsArr2BytesArr();
        }

        public override byte[] Hash(Stream stream)
        {
            if (!stream.CanRead)
                throw new IOException("Cannot read stream.");

            // Initial values
            ulong[] hash =
            {
                0x6a09e667f3bcc908, // H_0
                0xbb67ae8584caa73b, // H_1
                0x3c6ef372fe94f82b, // H_2
                0xa54ff53a5f1d36f1, // H_3
                0x510e527fade682d1, // H_4
                0x9b05688c2b3e6c1f, // H_5
                0x1f83d9abfb41bd6b, // H_6
                0x5be0cd19137e2179  // H_7
            };

            var w = new ulong[80]; // W_0 -> W_79, Message Schedule

            var lengthAppended = false;
            var hasBeenPadded = false;
            int readByteCount;
            // Read and compute as long as the final length bytes have not yet been appended
            while (!lengthAppended)
            {
                // Read in current block and pad if necessary
                readByteCount = ReadInBlock(stream, out var buffer, 128);

                if (readByteCount != buffer.Length && !hasBeenPadded) // Only add the 0x80 byte when it's not already been added
                {
                    buffer[readByteCount] = 0x80; // Padding byte
                    hasBeenPadded = true;
                }
                if (readByteCount < 112) // If there is room for the length bytes, append them ... 
                    // (including the padding byte in the case of the padding consists of only the padding byte)
                {
                    AppendLength(buffer, stream.Length);
                    lengthAppended = true; // ... and mark this block as the last
                }

                // --- Computation ---

                var m = buffer.BytesArr2ULongArr(); // M_0 -> M_15, Current Block

                // 1. Prepare the message schedule W:
                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (var t in Enumerable.Range(start: 16, count: 64))
                    w[t] = SmallSigma1(w[t - 2]) + w[t - 7] + SmallSigma0(w[t - 15]) + w[t - 16];

                // 2. Initialize the working variables:
                var a = hash[0];
                var b = hash[1];
                var c = hash[2];
                var d = hash[3];
                var e = hash[4];
                var f = hash[5];
                var g = hash[6];
                var h = hash[7];

                // 3. Perform the main hash computation:
                foreach (var t in Enumerable.Range(0, 80))
                {
                    var t1 = h + BigSigma1(e) + Ch(e, f, g) + K512[t] + w[t];
                    var t2 = BigSigma0(a) + Maj(a, b, c);
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

            return hash.ULongsArr2BytesArr();
        }

        public override string GetName() => "SHA2-512";
    }
}
