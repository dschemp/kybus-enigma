using System;
using Kybus.Enigma.Hashing;

namespace Kybus.Enigma.Padding
{
    public static class LengthPadding
    {
        public static byte[] PadToBlockSize(byte[] buffer, long blockSize, int lengthSize = 8, bool appendLengthInLittleEndian = false, bool appendLengthInBits = true)
        {
            long currentLength = buffer.GetLongLength(0);
            long newArrayLength = CalcNewArrayLength(currentLength, blockSize, lengthSize); // Excluding appended length bytes

            if (buffer == null)
            {
                buffer = new byte[0];
            }

            byte[] outputArray = new byte[newArrayLength + lengthSize]; // amount of bytes for the length bytes

            // copy exisiting stuff into new array
            Array.Copy(buffer, 0, outputArray, 0, currentLength);

            // pad first with a 1 bit / 0x80 byte, rest is already filled with \0 bytes
            outputArray[buffer.Length] = 0x80;

            // append the length bytes to the output array in LE
            AppendLength(outputArray, currentLength, appendLengthInLittleEndian, appendLengthInBits);

            return outputArray;
        }

        private static long CalcNewArrayLength(long currentLength, long blockSize, int lengthSize)
        {
            if (currentLength % blockSize == blockSize - lengthSize)
            {
                return currentLength + blockSize;
            }

            while (currentLength % blockSize != blockSize - lengthSize)
            {
                currentLength++; // TODO: Improve
            }

            return currentLength;
        }

        /// <summary>
        /// Part of the common padding method for hashing; appends the buffer length to the end of the buffer. (In BE or LE mode)
        /// </summary>
        private static void AppendLength(byte[] buffer, long originalLength, bool littleEndian, bool appendLengthInBits)
        {
            // TODO: Use BigInteger
            long size = appendLengthInBits ? originalLength * 8 : originalLength; // originalLength = length in bytes, i.e. we have to multiply with 8 to convert it into bits
            byte[] lengthBytes = littleEndian ? size.Int64ToUInt8ArrLE() : size.Int64LongToUInt8Arr();

            for (int i = 0; i < 8; i++)
            {
                buffer[buffer.Length - 8 + i] |= lengthBytes[i]; // Bits
            }
        }
    }
}
