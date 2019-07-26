using KybusEnigma.Lib.Symmetric;
using KybusEnigma.XUnit.Helper;
using Xunit;

namespace KybusEnigma.XUnit
{
    public class UnitTestAES
    {
        /*
         * Test parameters from the official NIST FIPS 197 document
         */

        #region Global Variables

        readonly Aes _aes128, _aes192, _aes256;
        readonly Aes _aes128cbc, _aes192cbc, _aes256cbc;
        readonly byte[] _key128, _key192, _key256;
        readonly byte[] _data;
        readonly byte[] _cbcInitVector;

        #endregion

        #region Setup / Initialization

        public UnitTestAES()
        {
            _key128 = HexBin.Decode("000102030405060708090a0b0c0d0e0f");
            _key192 = HexBin.Decode("000102030405060708090a0b0c0d0e0f1011121314151617");
            _key256 = HexBin.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

            _cbcInitVector = HexBin.Decode("00112233445566778899aabbccddeeff");

            _aes128 = new Aes(_key128);
            _aes192 = new Aes(_key192);
            _aes256 = new Aes(_key256);

            _aes128cbc = new Aes(_key128, _cbcInitVector);
            _aes192cbc = new Aes(_key192, _cbcInitVector);
            _aes256cbc = new Aes(_key256, _cbcInitVector);

            _data = HexBin.Decode("00112233445566778899aabbccddeeff");
        }

        #endregion

        #region AES-128

        [Fact(DisplayName = "AES-128 Encryption")]
        void Aes128_encrypt()
        {
            var ciphertext = _aes128.Encrypt(_data);
            var expected = HexBin.Decode("69c4e0d86a7b0430d8cdb78070b4c55a");
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-128 Decryption")]
        void Aes128_decrypt()
        {
            var ciphertext = HexBin.Decode("69c4e0d86a7b0430d8cdb78070b4c55a");
            var plaintext = _aes128.Decrypt(ciphertext);
            CustomAssert.MatchArrays(plaintext, _data);
        }

        #endregion

        #region AES-192

        [Fact(DisplayName = "AES-192 Encryption")]
        void Aes192_encrypt()
        {
            var ciphertext = _aes192.Encrypt(_data);
            var expected = HexBin.Decode("dda97ca4864cdfe06eaf70a0ec0d7191");
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-192 Decryption")]
        void Aes192_decrypt()
        {
            var ciphertext = HexBin.Decode("dda97ca4864cdfe06eaf70a0ec0d7191");
            var plaintext = _aes192.Decrypt(ciphertext);
            CustomAssert.MatchArrays(plaintext, _data);
        }

        #endregion

        #region AES-256

        [Fact(DisplayName = "AES-256 Encryption")]
        void Aes256_encrypt()
        {
            var ciphertext = _aes256.Encrypt(_data);
            var expected = HexBin.Decode("8ea2b7ca516745bfeafc49904b496089");
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-256 Decryption")]
        void Aes256_decrypt()
        {
            var ciphertext = HexBin.Decode("8ea2b7ca516745bfeafc49904b496089");
            var plaintext = _aes256.Decrypt(ciphertext);
            CustomAssert.MatchArrays(plaintext, _data);
        }

        #endregion

        #region AES-128 (CBC)

        [Fact(DisplayName = "AES-128 Encryption (CBC Mode)")]
        void Aes128cbc_encrypt()
        {
            var ciphertext = _aes128.Encrypt(_data);
            var expected = HexBin.Decode("69c4e0d86a7b0430d8cdb78070b4c55a");
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-128 Decryption (CBC Mode)")]
        void Aes128cbc_decrypt()
        {
            var ciphertext = HexBin.Decode("69c4e0d86a7b0430d8cdb78070b4c55a");
            var plaintext = _aes128.Decrypt(ciphertext);
            CustomAssert.MatchArrays(plaintext, _data);
        }

        #endregion

        #region AES-192 (CBC)

        [Fact(DisplayName = "AES-192 Encryption (CBC Mode)")]
        void Aes192cbc_encrypt()
        {
            var ciphertext = _aes192.Encrypt(_data);
            var expected = HexBin.Decode("dda97ca4864cdfe06eaf70a0ec0d7191");
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-192 Decryption (CBC Mode)")]
        void Aes192cbc_decrypt()
        {
            var ciphertext = HexBin.Decode("dda97ca4864cdfe06eaf70a0ec0d7191");
            var plaintext = _aes192.Decrypt(ciphertext);
            CustomAssert.MatchArrays(plaintext, _data);
        }

        #endregion

        #region AES-256 (CBC)

        [Fact(DisplayName = "AES-256 Encryption (CBC Mode)")]
        void Aes256cbc_encrypt()
        {
            var ciphertext = _aes256.Encrypt(_data);
            var expected = HexBin.Decode("8ea2b7ca516745bfeafc49904b496089");
            CustomAssert.MatchArrays(ciphertext, expected);
        }

        [Fact(DisplayName = "AES-256 Decryption (CBC Mode)")]
        void Aes256cbc_decrypt()
        {
            var ciphertext = HexBin.Decode("8ea2b7ca516745bfeafc49904b496089");
            var plaintext = _aes256.Decrypt(ciphertext);
            CustomAssert.MatchArrays(plaintext, _data);
        }

        #endregion
    }
}