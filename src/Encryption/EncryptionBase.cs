using System;
using System.Collections.Generic;
using System.Text;

namespace KybusEnigma.Lib.Encryption
{
    public abstract class EncryptionBase
    {
        public abstract byte[] Encrypt(byte[] plainText);
        public abstract byte[] Decrypt(byte[] cipherText);
    }
}
