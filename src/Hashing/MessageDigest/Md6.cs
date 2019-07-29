using System;

namespace KybusEnigma.Lib.Hashing.MessageDigest
{
    public sealed class Md6 : MessageDigestBase
    {
        public override byte[] Hash(byte[] data)
        {
            throw new NotImplementedException();
        }

        public override string GetName() => "MD6";
    }
}
