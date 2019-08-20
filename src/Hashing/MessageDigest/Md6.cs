using System;
using System.IO;

namespace KybusEnigma.Hashing.MessageDigest
{
    public sealed class Md6 : MessageDigestBase
    {
        public override string Name => "MD6";

        public override int HashLength => -1;

        public override byte[] Hash(byte[] data)
        {
            throw new NotImplementedException();
        }

        public override byte[] Hash(Stream stream)
        {
            throw new NotImplementedException();
        }
    }
}
