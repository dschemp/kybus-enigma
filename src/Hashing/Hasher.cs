using System.IO;

namespace KybusEnigma.Lib.Hashing
{
    public abstract class Hasher
    {
        public abstract byte[] Hash(byte[] data);
        public abstract byte[] Hash(Stream stream);
        public abstract string Name { get; }
        public abstract int HashLength { get; }

        #region Common Methods

        protected int ReadInBlock(Stream s, out byte[] buffer, int bufferSize = 64)
        {
            int byteCount = 0;
            int currentByte;
            buffer = new byte[bufferSize];

            while (byteCount < buffer.Length && (currentByte = s.ReadByte()) != -1)
                buffer[byteCount++] = (byte)currentByte;

            return byteCount;
        }

        #endregion

    }
}
