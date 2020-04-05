using System.IO;

namespace Kybus.Enigma.Hashing
{
    public abstract class Hasher
    {
        public abstract byte[] Hash(byte[] data);

        public abstract byte[] Hash(Stream stream);

        public abstract string Name { get; }

        /// <summary>
        /// Bit Length of Hash Result / Message Digest; -1 indicates a variable length / no fixed length.
        /// </summary>
        public abstract int HashLength { get; }

        #region Common Methods

        /// <summary>
        ///  Read in a block from a stream and fill with 0s
        /// </summary>
        protected int ReadInBlock(Stream s, out byte[] buffer, int bufferSize = 64)
        {
            int byteCount = 0;
            int currentByte;
            buffer = new byte[bufferSize];

            while (byteCount < buffer.Length && (currentByte = s.ReadByte()) != -1)
            {
                buffer[byteCount++] = (byte)currentByte;
            }

            return byteCount;
        }

        /// <summary>
        /// Part of the common padding method for hashing; appends the buffer length to the end of the buffer. (In BE or LE mode)
        /// </summary>
        protected void AppendLength(byte[] buffer, long originalLength, bool littleEndian = false)
        {
            // TODO: Use BigInteger
            long size = originalLength * 8; // originalLength = length in bytes, i.e. we have to multiply with 8 to convert it into bits
            byte[] lengthBytes = littleEndian ? size.Int64ToUInt8ArrLE() : size.Int64LongToUInt8Arr();

            for (int i = 0; i < 8; i++)
            {
                buffer[buffer.Length - 8 + i] |= lengthBytes[i]; // Bits
            }
        }

        #endregion

    }
}
