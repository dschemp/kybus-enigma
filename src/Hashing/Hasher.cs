using System.IO;

namespace KybusEnigma.Lib.Hashing
{
    public abstract class Hasher
    {
        public abstract byte[] Hash(byte[] data);
        public abstract byte[] Hash(Stream stream);
        public abstract string GetName();
    }
}
