using System.Numerics;

namespace KybusEnigma.Lib.Encryption.Asymmetric
{
    /// <summary>
    /// !!! UNTESTED !!!
    /// </summary>
    public class Rsa : EncryptionBase
    {
        public byte[] RsaModulus { get; set; }
        public AsymmetricKeyPair KeyPair { get; set; }

        public Rsa(byte[] rsaModulus, byte[] publicKey, byte[] privateKey)
        {
            this.RsaModulus = rsaModulus;
            this.KeyPair = new AsymmetricKeyPair(publicKey, privateKey);
        }

        public Rsa(byte[] rsaModulus, AsymmetricKeyPair keyPair) : this(rsaModulus, keyPair.PublicKey, keyPair.PrivateKey) { }

        public Rsa() { }

        public static Rsa Create() => new Rsa();

        public override byte[] Encrypt(byte[] plainText) => BigInteger.ModPow(new BigInteger(plainText), new BigInteger(RsaModulus), new BigInteger(KeyPair.PublicKey)).ToByteArray();

        public override byte[] Decrypt(byte[] cipherText) => BigInteger.ModPow(new BigInteger(cipherText), new BigInteger(KeyPair.PrivateKey), new BigInteger(RsaModulus)).ToByteArray();
    }
}
