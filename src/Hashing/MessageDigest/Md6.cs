using System;
using System.IO;

namespace KybusEnigma.Lib.Hashing.MessageDigest
{
    public sealed class Md6 : MessageDigestBase
    {
        public override byte[] Hash(byte[] data)
        {
            throw new NotImplementedException();
        }

        public override byte[] Hash(Stream stream)
        {
            throw new NotImplementedException();
        }

        public override string GetName() => "MD6";
    }
}
