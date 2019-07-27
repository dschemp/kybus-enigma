using System;

namespace KybusEnigma.Lib.Hashing.MessageDigest
{
    public sealed class Md6 : MessageDigestBase
    {
        public override byte[] Hash(byte[] arr)
        {
            throw new NotImplementedException();
        }

        public override string GetName() => "MD6";
    }
}
