using System;
using System.Collections.Generic;

namespace KybusEnigma.Lib.Encryption.Symmetric
{
    public sealed class Aes : EncryptionBase
    {
        #region Generate Instance with Key

        public enum KeyLength
        {
            Key128 = 128, Key192 = 192, Key256 = 256
        }

        #endregion

        #region Key Handling

        private byte[] _key;
        public byte[] Key
        {
            get => _key;
            set => SetKey(value);
        }

        public KeyLength Mode { get; private set; }

        private void SetKey(byte[] key)
        {
            // Only valid key lengths 128, 192 and 256 bits (16, 24 and 24 bytes respectively)
            if (key != null && key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                throw new ArgumentException("Key length must be 128, 192 or 256 bits [16, 24 or 32 bytes respectively] long!");
            }
            this._key = key;
            this.Mode = (KeyLength) (8 * key.Length);

            this._rounds = (Key.Length / 4) + 6; // Only invalid in case the key length is 224 bits but AES only supports 128/192/256

            // When setting the key, generate the expanded key and place it in the variable
            var expandedKey = ExpandKey(key, key.Length / 4);
            ExpandedKey = expandedKey;
        }

        #endregion

        #region Misc

        private int _rounds;

        private readonly byte[] _rcon = { 0x02, 0x00, 0x00, 0x00 };

        #endregion

        #region CBC Mode

        private byte[] _cbcInitVector;
        public byte[] CbcInitVector
        {
            get => _cbcInitVector;
            set => SetCbc(value);
        }

        public bool CbcModeEnabled => _cbcInitVector != null;

        private void SetCbc(byte[] vec)
        {
            if (vec != null && vec.Length != 16)
                throw new ArgumentException("CBC Initialization Vector must be 128 bits [16 bytes] long!");

            _cbcInitVector = vec;
        }

        #endregion

        #region Expanded Key + Getter and Setter

        private byte[] ExpandedKey { get; set; }

        #endregion

        #region SBoxes

        // SBox[x, y]
        private readonly byte[,] _sBox = {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, },
            { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, },
            { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, },
            { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, },
            { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, },
            { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, },
            { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, },
            { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, },
            { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, },
            { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, },
            { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, },
            { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, },
            { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, },
            { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, },
            { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
        };

        // InvSBox[x, y]
        private readonly byte[,] _invSBox = {
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };

        #endregion

        private Aes(byte[] key, byte[] cbcInitVector = null)
        {
            this.Key = key;
            this.CbcInitVector = cbcInitVector;
        }

        public static EncryptionBase Create(byte[] key) => new Aes(key);

        public static EncryptionBase CreateWithRandomKey(int lengthInBits)
        {
            if (lengthInBits != 128 || lengthInBits != 192 || lengthInBits != 256)
                throw new ArgumentOutOfRangeException("Key length must be 128, 192 or 256 bits!");

            var arr = new byte[lengthInBits / 8];
            using (var rnd = System.Security.Cryptography.RandomNumberGenerator.Create())
                rnd.GetBytes(arr);
            return new Aes(arr);
        }

        #region Wrapper Methods

        public override byte[] Encrypt(byte[] plainText)
        {
            var blocks = (int)Math.Ceiling(plainText.Length / 16.0);
            var output = new byte[blocks * 16];
            byte[] lastBlock = null;

            for (var i = 0; i < blocks; i++)
            {
                var cbcVector = CbcModeEnabled ? (i == 0 ? CbcInitVector : lastBlock) : null;

                var start = i * 16;
                var end = (i + 1) * 16;
                var block = new byte[16];

                for (var l = start; l < end; l++)
                {
                    block[l - start] = (plainText.Length > l) ? plainText[l] : (byte)0x0;
                }

                var cipherText = EncryptBlock(block, cbcVector);
                for (var j = start; j < end; j++)
                {
                    output[j] = cipherText[j - start];
                }

                lastBlock = cipherText;
            }
            return output;
        }

        public override byte[] Decrypt(byte[] encryptedData)
        {
            var blocks = (int)Math.Ceiling(encryptedData.Length / 16.0);
            var output = new byte[blocks * 16];
            byte[] lastBlock = null;

            for (var i = 0; i < blocks; i++)
            {
                var cbcVector = CbcModeEnabled ? (i == 0 ? CbcInitVector : lastBlock) : null;

                var start = i * 16;
                var end = (i + 1) * 16;
                var block = new byte[16];

                for (var l = start; l < end; l++)
                {
                    block[l - start] = (encryptedData.Length > l) ? encryptedData[l] : (byte)0x0;
                }

                var cipherText = DecryptBlock(block, cbcVector);
                for (var j = start; j < end; j++)
                {
                    output[j] = cipherText[j - start];
                }

                lastBlock = cipherText;
            }
            return output;
        }

        #endregion

        #region Encrypt / Decrypt Block

        private byte[] EncryptBlock(byte[] data, byte[] cbcVector)
        {
            if (CbcModeEnabled) data.ApplyXorTo(cbcVector);

            var state = data.ConvertArrayToState();

            AddRoundKey(state, 0);

            for (var r = 1; r < _rounds; r++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, r);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, _rounds);

            var encryptedData = state.ConvertStateToByteArray();
            return encryptedData;
        }

        private byte[] DecryptBlock(byte[] encryptedData, byte[] cbcVector)
        {
            var state = encryptedData.ConvertArrayToState();

            AddRoundKey(state, _rounds);

            for (var r = _rounds - 1; r >= 1; r--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, r);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, 0);

            var decryptedData = state.ConvertStateToByteArray();

            if (CbcModeEnabled) decryptedData.ApplyXorTo(cbcVector);

            return decryptedData;
        }

        #endregion

        #region AddRoundKey Method (for en- and decryption)

        private void AddRoundKey(byte[,] state, int round)
        {
            for (var c = 0; c < 4; c++)
            {
                state[c, 0] ^= ExpandedKey[4 * 4 * round + 4 * c + 0];
                state[c, 1] ^= ExpandedKey[4 * 4 * round + 4 * c + 1];
                state[c, 2] ^= ExpandedKey[4 * 4 * round + 4 * c + 2];
                state[c, 3] ^= ExpandedKey[4 * 4 * round + 4 * c + 3];
            }
        }

        #endregion

        #region Encryption Methods

        private void SubBytes(byte[,] state)
        {
            for (var i = 0; i < 16; i++)
            {
                var x = i / 4;
                var y = i % 4;

                var firstNum = (state[x, y] & 0xf0) >> 4;
                var secondNum = (state[x, y] & 0xf);

                state[x, y] = _sBox[firstNum, secondNum];
            }
        }

        private static void ShiftRows(byte[,] state)
        {
            var tempState = state.DeepCopyStateArray();

            // go through each row, starting at 1 because no bytes are shifted at 0
            for (var y = 1; y < 4; y++)
            {
                for (var x = 0; x < 4; x++)
                {
                    var newX = (x + y) % 4;
                    state[x, y] = tempState[newX, y];
                }
            }
        }

        private static void MixColumns(byte[,] state)
        {
            var tempState = state.DeepCopyStateArray();

            for (var x = 0; x < 4; x++)
            {
                state[x, 0] = (byte)(BitwiseMultiplication((byte)0x2, tempState[x, 0]) ^ BitwiseMultiplication((byte)0x3, tempState[x, 1]) ^ tempState[x, 2] ^ tempState[x, 3]);
                state[x, 1] = (byte)(tempState[x, 0] ^ BitwiseMultiplication((byte)0x2, tempState[x, 1]) ^ BitwiseMultiplication((byte)0x3, tempState[x, 2]) ^ tempState[x, 3]);
                state[x, 2] = (byte)(tempState[x, 0] ^ tempState[x, 1] ^ BitwiseMultiplication((byte)0x2, tempState[x, 2]) ^ BitwiseMultiplication((byte)0x3, tempState[x, 3]));
                state[x, 3] = (byte)(BitwiseMultiplication((byte)0x3, tempState[x, 0]) ^ tempState[x, 1] ^ tempState[x, 2] ^ BitwiseMultiplication((byte)0x2, tempState[x, 3]));
            }
        }

        #endregion

        #region Decryption (Inverse) Methods

        private void InvSubBytes(byte[,] state)
        {
            for (var i = 0; i < 16; i++)
            {
                var x = i / 4;
                var y = i % 4;

                var firstNum = (state[x, y] & 0xf0) >> 4;
                var secondNum = (state[x, y] & 0xf);

                state[x, y] = _invSBox[firstNum, secondNum];
            }
        }

        private static void InvShiftRows(byte[,] state)
        {
            var tempState = state.DeepCopyStateArray();

            // go through each row, starting at 1 because no bytes are shifted at 0
            for (var y = 1; y < 4; y++)
            {
                for (var x = 0; x < 4; x++)
                {
                    var newX = (x + 4 - y) % 4;
                    state[x, y] = tempState[newX, y];
                }
            }
        }

        private static void InvMixColumns(byte[,] state)
        {
            var tempState = state.DeepCopyStateArray();

            for (var x = 0; x < 4; x++)
            {
                state[x, 0] = (byte) (BitwiseMultiplication((byte) 0x0e, tempState[x, 0]) ^
                                          BitwiseMultiplication((byte) 0x0b, tempState[x, 1]) ^
                                          BitwiseMultiplication((byte) 0x0d, tempState[x, 2]) ^
                                          BitwiseMultiplication((byte) 0x09, tempState[x, 3]));
                state[x, 1] = (byte) (BitwiseMultiplication((byte) 0x09, tempState[x, 0]) ^
                                          BitwiseMultiplication((byte) 0x0e, tempState[x, 1]) ^
                                          BitwiseMultiplication((byte) 0x0b, tempState[x, 2]) ^
                                          BitwiseMultiplication((byte) 0x0d, tempState[x, 3]));
                state[x, 2] = (byte) (BitwiseMultiplication((byte) 0x0d, tempState[x, 0]) ^
                                          BitwiseMultiplication((byte) 0x09, tempState[x, 1]) ^
                                          BitwiseMultiplication((byte) 0x0e, tempState[x, 2]) ^
                                          BitwiseMultiplication((byte) 0x0b, tempState[x, 3]));
                state[x, 3] = (byte) (BitwiseMultiplication((byte) 0x0b, tempState[x, 0]) ^
                                          BitwiseMultiplication((byte) 0x0d, tempState[x, 1]) ^
                                          BitwiseMultiplication((byte) 0x09, tempState[x, 2]) ^
                                          BitwiseMultiplication((byte) 0x0e, tempState[x, 3]));
            }
        }

        #endregion

        #region Key Expansion

        private byte[] ExpandKey(byte[] key, int nk)
        {
            var words = new byte[4 * 4 * (_rounds + 1)];

            var temp = new byte[4]; // Word

            var i = 0;

            while (i < nk)
            {
                words[4 * i] = key[4 * i];
                words[4 * i + 1] = key[4 * i + 1];
                words[4 * i + 2] = key[4 * i + 2];
                words[4 * i + 3] = key[4 * i + 3];
                i++;
            }

            i = nk;

            while (i < 4 * (_rounds + 1))
            {
                temp[0] = words[4 * (i - 1)];
                temp[1] = words[4 * (i - 1) + 1];
                temp[2] = words[4 * (i - 1) + 2];
                temp[3] = words[4 * (i - 1) + 3];

                if (i % nk == 0)
                {
                    temp = RotWord(temp);
                    temp = SubWord(temp);
                    temp = CoefAdd(temp, Rcon(((byte)(i / nk))));
                }
                else if (nk > 6 && i % nk == 4)
                {
                    temp = SubWord(temp);
                }

                words[4 * i] = ((byte)(words[4 * (i - nk)] ^ temp[0]));
                words[4 * i + 1] = ((byte)(words[4 * (i - nk) + 1] ^ temp[1]));
                words[4 * i + 2] = ((byte)(words[4 * (i - nk) + 2] ^ temp[2]));
                words[4 * i + 3] = ((byte)(words[4 * (i - nk) + 3] ^ temp[3]));

                i++;
            }
            return words;
        }

        #region Adopted from another source

        private static byte[] CoefAdd(IReadOnlyList<byte> word, IReadOnlyList<byte> word2)
        {
            var temp = new byte[4];

            temp[0] = ((byte)(word[0] ^ word2[0]));
            temp[1] = ((byte)(word[1] ^ word2[1]));
            temp[2] = ((byte)(word[2] ^ word2[2]));
            temp[3] = ((byte)(word[3] ^ word2[3]));

            return temp;
        }

        private byte[] Rcon(byte i)
        {

            if (i == 1)
            {
                _rcon[0] = 0x01; // x^(1-1) = x^0 = 1
            }
            else if (i > 1)
            {
                _rcon[0] = 0x02;
                i--;
                while (i - 1 > 0)
                {
                    _rcon[0] = BitwiseMultiplication(_rcon[0], (byte)0x02);
                    i--;
                }
            }

            return _rcon;
        }

        private static byte BitwiseMultiplication(byte a, byte b)
        {
            byte p = (byte)0x0, i;

            for (i = 0; i < 8; i++)
            {
                if ((b & (byte)0x1) != 0)
                {
                    p ^= a;
                }

                var hbs = (byte)(a & 0x80);
                a <<= 1;
                if (hbs != 0) a ^= 0x1b; // 0000 0001 0001 1011
                b >>= 1;
            }

            return p;
        }

        #endregion

        private byte[] SubWord(byte[] word)
        {
            for (var i = 0; i < word.Length; i++)
            {
                var firstNum = (word[i] & 0xF0) >> 4;
                var secondNum = (word[i] & 0x0F);

                word[i] = _sBox[firstNum, secondNum];
            }

            return word;
        }

        private static byte[] RotWord(byte[] word)
        {
            var first = word[0];

            // Shift all bytes one byte to the left
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = first;

            return word;
        }

        #endregion
    }

    #region Array Transformation Helper Classes

    static class AesExtensions
    {
        public static void ApplyXorTo(this byte[] plainText, byte[] data)
        {
            for (var i = 0; i < 16; i++)
            {
                plainText[i] ^= data[i];
            }
        }

        public static byte[,] ConvertArrayToState(this byte[] arr)
        {
            var state = new byte[4, 4];

            // Befuelt das State Array aus dem Data Byte Array
            for (var i = 0; i < 16; i++)
            {
                var x = i / 4;
                var y = i % 4;

                state[x, y] = arr[i];
            }

            return state;
        }

        public static byte[] ConvertStateToByteArray(this byte[,] state)
        {
            if (state == null)
                return null;

            var bytes = new byte[16];
            for (var i = 0; i < 16; i++)
            {
                var x = i / 4;
                var y = i % 4;

                bytes[i] = state[x, y];
            }

            return bytes;
        }

        public static byte[,] DeepCopyStateArray(this byte[,] state)
        {
            return (byte[,])state.Clone();
        }
    }

    #endregion
}