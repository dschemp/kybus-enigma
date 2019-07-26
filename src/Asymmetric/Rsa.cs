using System.Numerics;

namespace KybusEnigma.Lib.Asymmetric
{
    /// <summary>
    /// !!! UNTESTED !!!
    /// </summary>
    class Rsa
    {
        public byte[] Encrypt(byte[] data, BigInteger n, BigInteger e)
        {
            var b = new BigInteger(data);
            return BigInteger.ModPow(b, n, e).ToByteArray();
        }

        public byte[] Decrypt(byte[] encryptedData, BigInteger n, BigInteger d)
        {
            var b = new BigInteger(encryptedData);
            return BigInteger.ModPow(b, d, n).ToByteArray();
        }
    }
}
