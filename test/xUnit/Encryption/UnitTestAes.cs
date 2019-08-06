using KybusEnigma.Lib.Encryption.Symmetric;
using KybusEnigma.xUnit.Helper;
using Xunit;

namespace KybusEnigma.xUnit.Encryption
{
    public class UnitTestAes
    {
        /*
         * Test parameters from the official NIST FIPS 197 document
         */

        #region Global Variables

        public Aes Aes128, Aes192, Aes256;
        public Aes Aes128Cbc, Aes192Cbc, Aes256Cbc;
        public byte[] Key128, Key192, Key256;
        public byte[] CbcInitVector;

        public TestVectorContainer<string, byte[], string, byte[]> TestVectors;

        #endregion

        #region Setup / Initialization

        public UnitTestAes()
        {
            Key128 = Converter.HexByteDecode("000102030405060708090a0b0c0d0e0f");
            Key192 = Converter.HexByteDecode("000102030405060708090a0b0c0d0e0f1011121314151617");
            Key256 = Converter.HexByteDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

            CbcInitVector = Converter.HexByteDecode("00112233445566778899aabbccddeeff");

            Aes128 = Aes.Create(Key128);
            Aes192 = Aes.Create(Key192);
            Aes256 = Aes.Create(Key256);

            Aes128Cbc = Aes.Create(Key128, CbcInitVector);
            Aes192Cbc = Aes.Create(Key192, CbcInitVector);
            Aes256Cbc = Aes.Create(Key256, CbcInitVector);

            const string data = "00112233445566778899aabbccddeeff";

            TestVectors = new TestVectorContainer<string, byte[], string, byte[]>(Converter.HexByteDecode, Converter.HexByteDecode)
            {
                {"AES-128 Encryption"           , data, "69c4e0d86a7b0430d8cdb78070b4c55a" },
                {"AES-128 Decryption"           , "69c4e0d86a7b0430d8cdb78070b4c55a", data },

                {"AES-192 Encryption"           , data, "dda97ca4864cdfe06eaf70a0ec0d7191" },
                {"AES-192 Decryption"           , "dda97ca4864cdfe06eaf70a0ec0d7191", data },

                {"AES-256 Encryption"           , data, "8ea2b7ca516745bfeafc49904b496089" },
                {"AES-256 Decryption"           , "8ea2b7ca516745bfeafc49904b496089", data },

                {"AES-128 Encryption (CBC Mode)", data, "c6a13b37878f5b826f4f8162a1c8d879" },
                {"AES-128 Decryption (CBC Mode)", "c6a13b37878f5b826f4f8162a1c8d879", data },

                {"AES-192 Encryption (CBC Mode)", data, "916251821c73a522c396d62738019607" },
                {"AES-192 Decryption (CBC Mode)", "916251821c73a522c396d62738019607", data },

                {"AES-256 Encryption (CBC Mode)", data, "f29000b62a499fd0a9f39a6add2e7780" },
                {"AES-256 Decryption (CBC Mode)", "f29000b62a499fd0a9f39a6add2e7780", data },
            };
        }

        #endregion

        #region AES-128

        [Fact(DisplayName = "AES-128 Encryption")]
        public void Aes128_encrypt()
        {
            var (data, expected) = TestVectors.Get("AES-128 Encryption");

            var ciphertext = Aes128.Encrypt(data);
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-128 Decryption")]
        public void Aes128_decrypt()
        {
            var (data, expected) = TestVectors.Get("AES-128 Decryption");

            var plaintext = Aes128.Decrypt(data);
            CustomAssert.MatchArrays(plaintext, expected);
        }

        #endregion

        #region AES-192

        [Fact(DisplayName = "AES-192 Encryption")]
        public void Aes192_encrypt()
        {
            var (data, expected) = TestVectors.Get("AES-192 Encryption");

            var ciphertext = Aes192.Encrypt(data);
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-192 Decryption")]
        public void Aes192_decrypt()
        {
            var (data, expected) = TestVectors.Get("AES-192 Decryption");

            var plaintext = Aes192.Decrypt(data);
            CustomAssert.MatchArrays(plaintext, expected);
        }

        #endregion

        #region AES-256

        [Fact(DisplayName = "AES-256 Encryption")]
        public void Aes256_encrypt()
        {
            var (data, expected) = TestVectors.Get("AES-256 Encryption");

            var ciphertext = Aes256.Encrypt(data);
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-256 Decryption")]
        public void Aes256_decrypt()
        {
            var (data, expected) = TestVectors.Get("AES-256 Decryption");

            var plaintext = Aes256.Decrypt(data);
            CustomAssert.MatchArrays(plaintext, expected);
        }

        #endregion

        #region AES-128 (CBC)

        [Fact(DisplayName = "AES-128 Encryption (CBC Mode)")]
        public void Aes128cbc_encrypt()
        {
            var (data, expected) = TestVectors.Get("AES-128 Encryption (CBC Mode)");

            var ciphertext = Aes128Cbc.Encrypt(data);
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-128 Decryption (CBC Mode)")]
        public void Aes128cbc_decrypt()
        {
            var (data, expected) = TestVectors.Get("AES-128 Decryption (CBC Mode)");

            var plaintext = Aes128Cbc.Decrypt(data);
            CustomAssert.MatchArrays(plaintext, expected);
        }

        #endregion

        #region AES-192 (CBC)

        [Fact(DisplayName = "AES-192 Encryption (CBC Mode)")]
        public void Aes192cbc_encrypt()
        {
            var (data, expected) = TestVectors.Get("AES-192 Encryption (CBC Mode)");

            var ciphertext = Aes192Cbc.Encrypt(data);
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-192 Decryption (CBC Mode)")]
        public void Aes192cbc_decrypt()
        {
            var (data, expected) = TestVectors.Get("AES-192 Decryption (CBC Mode)");

            var plaintext = Aes192Cbc.Decrypt(data);
            CustomAssert.MatchArrays(plaintext, expected);
        }

        #endregion

        #region AES-256 (CBC)

        [Fact(DisplayName = "AES-256 Encryption (CBC Mode)")]
        public void Aes256cbc_encrypt()
        {
            var (data, expected) = TestVectors.Get("AES-256 Encryption (CBC Mode)");

            var ciphertext = Aes256Cbc.Encrypt(data);
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-256 Decryption (CBC Mode)")]
        public void Aes256cbc_decrypt()
        {
            var (data, expected) = TestVectors.Get("AES-256 Decryption (CBC Mode)");

            var plaintext = Aes256Cbc.Decrypt(data);
            CustomAssert.MatchArrays(plaintext, expected);
        }

        #endregion
    }
}