using System;

namespace KybusEnigma.Lib.Hashing.MessageDigest
{
    public class Md5 : MessageDigestBase
    {
        public override byte[] Hash(byte[] arr)
        {
            throw new NotImplementedException();
        }

        public override string GetName() => "MD5";
    }
}
