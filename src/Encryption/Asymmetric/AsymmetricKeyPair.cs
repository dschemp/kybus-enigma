namespace KybusEnigma.Lib.Encryption.Asymmetric
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
