using System;
using System.Runtime.CompilerServices;

namespace KybusEnigma.Lib.Hashing
{
    public abstract class Hasher
    {
        public abstract byte[] Hash(byte[] arr);
        public abstract string GetName();
    }
}
