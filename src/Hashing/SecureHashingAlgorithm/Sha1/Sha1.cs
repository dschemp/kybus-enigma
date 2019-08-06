using System;
using System.IO;
using System.Linq;

namespace KybusEnigma.Lib.Hashing.SecureHashingAlgorithm.Sha1
{
    public class Sha1 : Hasher
    {
        public override byte[] Hash(byte[] data)
        {
            var paddedInput = Pad(data);
            // Convert input byte array to uint array for processing
            var arr = paddedInput.BytesArr2UIntArr();

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
            var amountOfBlocks = arr.Length / 16;

            var m = new uint[16]; // M_0 -> M_15, Message Block
            var w = new uint[80]; // W_0 -> W_79, Message Schedule

            // Process each block
            for (var n = 0; n < amountOfBlocks; n++)
            {
                // Copy data into current message block
                Array.Copy(arr, n * m.Length, m, 0, m.Length);

                // 1. Prepare the message schedule W:
                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (var t in Enumerable.Range(16, 64))
                    w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).RotL(1);

                // 2. Initialize the working variables:
                var a = hash[0];
                var b = hash[1];
                var c = hash[2];
                var d = hash[3];
                var e = hash[4];

                // 3. Perform the main hash computation:
                foreach (var t in Enumerable.Range(0, 80))
                {
                    var temp = a.RotL(5) + F(t, b, c, d) + e + w[t] + K(t);
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

            return hash.UIntsArr2BytesArr();
        }

        public override byte[] Hash(Stream stream)
        {
            if (!stream.CanRead)
                throw new IOException("Cannot read stream.");

            // Initial values
            uint[] hash =
            {
                0x67452301, // H_0
                0xEFCDAB89, // H_1
                0x98BADCFE, // H_2
                0x10325476, // H_3
                0xC3D2E1F0  // H_4
            };

            var w = new uint[80]; // W_0 -> W_79, Message Schedule

            var lengthAppended = false;
            var hasBeenPadded = false; 
            int readByteCount;
            // Read and compute as long as the final length bytes have not yet been appended
            while (!lengthAppended)
            {
                // Read in current block and pad if necessary
                readByteCount = ReadInBlock(stream, out var buffer);

                if (readByteCount != buffer.Length && !hasBeenPadded) // Only add the 0x80 byte when it's not already been added
                {
                    buffer[readByteCount] = 0x80; // Padding byte
                    hasBeenPadded = true;
                }
                if (readByteCount <= 48) // If there is room for the length bytes, append them ... 
                    // (including the padding byte in the case of the padding consists of only the padding byte)
                {
                    AppendLength(buffer, stream.Length);
                    lengthAppended = true; // ... and mark this block as the last
                }

                // --- Computation ---

                var m = buffer.BytesArr2UIntArr(); // M_0 -> M_15, Current Block

                Array.Copy(m, 0, w, 0, m.Length); // Copy first block into start of message schedule w
                foreach (var t in Enumerable.Range(16, 64))
                    w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).RotL(1);

                // 2. Initialize the working variables:
                var a = hash[0];
                var b = hash[1];
                var c = hash[2];
                var d = hash[3];
                var e = hash[4];

                // 3. Perform the main hash computation:
                foreach (var t in Enumerable.Range(0, 80))
                {
                    var temp = a.RotL(5) + F(t, b, c, d) + e + w[t] + K(t);
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

            return hash.UIntsArr2BytesArr();
        }

        public override string GetName() => "SHA-1";

        #region Helpers, Functions and Constants

        private static int CalcNewArrayLength(int length)
        {
            if (length % 64 == 56)
                return length + 64;

            while (length % 64 != 56) length++;
            return length;
        }

        private void AppendLength(byte[] buffer, long originalLength)
        {
            var lengthBytes = (originalLength * 8).Long2BytesArr(); // originalLength = length in bytes, i.e. we have to multiply with 8 to convert it into bits
            for (var i = 0; i < 8; i++)
                buffer[buffer.Length - 8 + i] |= lengthBytes[i]; // Bits
        }

        protected byte[] Pad(byte[] buffer)
        {
            if (buffer == null)
                buffer = new byte[0];

            var newArrayLength = CalcNewArrayLength(buffer.Length); // Not including padding bytes
            var outputArray = new byte[newArrayLength + 8];

            // copy exisiting stuff into new array
            Array.Copy(buffer, 0, outputArray, 0, buffer.Length);

            // pad first with a 1 bit / 0x80 byte, rest is already filled with \0 bytes
            outputArray[buffer.Length] = 0x80;

            // append the length bytes to the output array
            AppendLength(outputArray, buffer.GetLongLength(0));

            return outputArray;
        }

        protected uint F(int t, uint b, uint c, uint d)
        {
            if (t < 20)
                return (b & c) | (~b & d);
            if (t < 40)
                return b ^ c ^ d;
            if (t < 60)
                return (b & c) | (b & d) | (c & d);
            return b ^ c ^ d;
        }

        protected uint K(int t)
        {
            if (t < 20)
                return 0x5A827999;
            if (t < 40)
                return 0x6ED9EBA1;
            if (t < 60)
                return 0x8F1BBCDC;
            return 0xCA62C1D6;
        }

        #endregion
    }
}
