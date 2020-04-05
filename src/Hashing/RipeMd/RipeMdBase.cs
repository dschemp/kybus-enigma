namespace Kybus.Enigma.Hashing.RipeMd
{
    public abstract class RipeMdBase : Hasher
    {
        #region RIPEMD Functions

        // Five basic functions (J only in RIPEMD-160)
        protected uint F(uint x, uint y, uint z) => x ^ y ^ z;

        protected uint G(uint x, uint y, uint z) => (x & y) | (~x & z);

        protected uint H(uint x, uint y, uint z) => (x | ~y) ^ z;

        protected uint I(uint x, uint y, uint z) => (x & z) | (y & ~z);

        protected uint J(uint x, uint y, uint z) => x ^ (y | ~z);

        protected uint F(int j, uint x, uint y, uint z)
        {
            if (j < 16)
            {
                return F(x, y, z);
            }
            else if (j < 32)
            {
                return G(x, y, z);
            }
            else if (j < 48)
            {
                return H(x, y, z);
            }
            else if (j < 64)
            {
                return I(x, y, z);
            }
            else
            {
                return J(x, y, z);
            }
        }

        #endregion

        #region Constants (RIPEMD-160)

        protected uint K_160(int j)
        {
            if (j < 16)
            {
                return 0x00;
            }
            else if (j < 32)
            {
                return 0x5A827999;
            }
            else if (j < 48)
            {
                return 0x6ED9EBA1;
            }
            else if (j < 64)
            {
                return 0x8F1BBCDC;
            }
            else
            {
                return 0xA953FD4E;
            }
        }

        protected uint KDash_160(int j)
        {
            if (j < 16)
            {
                return 0x50A28BE6;
            }
            else if (j < 32)
            {
                return 0x5C4DD124;
            }
            else if (j < 48)
            {
                return 0x6D703EF3;
            }
            else if (j < 64)
            {
                return 0x7A6D76E9;
            }
            else
            {
                return 0x00000000;
            }
        }

        protected readonly int[] _r160 =
        {
            0,  1,  2,  3,  4,  5,  6,  7,  8, 9, 10, 11, 12, 13, 14, 15,
            7,  4, 13,  1, 10,  6, 15,  3, 12, 0,  9,  5,  2, 14, 11,  8,
            3, 10, 14,  4,  9, 15,  8,  1,  2, 7,  0,  6, 13, 11,  5, 12,
            1,  9, 11, 10,  0,  8, 12,  4, 13, 3,  7, 15, 14,  5,  6,  2,
            4,  0,  5,  9,  7, 12,  2, 10, 14, 1,  3,  8, 11,  6, 15, 13
        };

        protected readonly int[] _rDash160 =
        {
            5, 14,  7, 0, 9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
            6, 11,  3, 7, 0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
            15,  5,  1, 3, 7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
            8,  6,  4, 1, 3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
            12, 15, 10, 4, 1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
        };

        protected readonly int[] _s160 =
        {
            11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
            7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
            11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
            11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
            9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
        };

        protected readonly int[] _sDash160 =
        {
            8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
            9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
            9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
            15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
            8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
        };

        #endregion

        #region Constants (RIPEMD-128)

        protected uint K_128(int j)
        {
            if (j < 16)
            {
                return 0x00;
            }
            else if (j < 32)
            {
                return 0x5A827999;
            }
            else if (j < 48)
            {
                return 0x6ED9EBA1;
            }
            else
            {
                return 0x8F1BBCDC;
            }
        }

        protected uint KDash_128(int j)
        {
            if (j < 16)
            {
                return 0x50A28BE6;
            }
            else if (j < 32)
            {
                return 0x5C4DD124;
            }
            else if (j < 48)
            {
                return 0x6D703EF3;
            }
            else
            {
                return 0x00000000;
            }
        }

        protected readonly int[] _r128 =
        {
            0,  1,  2,  3,  4,  5,  6, 7,  8, 9, 10, 11, 12, 13, 14, 15,
            7,  4, 13,  1, 10,  6, 15, 3, 12, 0,  9,  5,  2, 14, 11,  8,
            3, 10, 14,  4,  9, 15,  8, 1,  2, 7,  0,  6, 13, 11,  5, 12,
            1,  9, 11, 10,  0,  8, 12, 4, 13, 3,  7, 15, 14,  5,  6,  2
        };

        protected readonly int[] _rDash128 =
        {
            5, 14, 7, 0, 9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
            6, 11, 3, 7, 0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
            15,  5, 1, 3, 7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
            8,  6, 4, 1, 3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14
        };

        protected readonly int[] _s128 =
        {
            11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
            7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
            11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
            11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12
        };

        protected readonly int[] _sDash128 =
        {
            8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
            9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
            9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
            15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8
        };

        #endregion
    }
}
