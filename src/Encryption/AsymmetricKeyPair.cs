using System;
using System.Collections.Generic;
using System.Text;

namespace KybusEnigma.Lib.Encryption
{
    public sealed class AsymmetricKeyPair
    {
        public byte[] PublicKey { get; set; }
        public byte[] PrivateKey { get; set; }

        public AsymmetricKeyPair(byte[] publicKey, byte[] privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }
    }
}
