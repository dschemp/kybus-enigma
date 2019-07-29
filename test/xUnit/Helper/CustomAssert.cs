using System;
using Xunit;

namespace KybusEnigma.xUnit.Helper
{
    internal class CustomAssert : Assert
    {
        public static void MatchArrays<T>(T[] input, T[] expected) where T : IComparable
        {
            if (input.Length != expected.Length)
                True(false, "Unequel Array Lengths");

            for (var i = 0; i < input.Length; i++)
            {
                if (input[i].CompareTo(expected[i]) != 0)
                    True(false, $"Unequel element at Index {i}. Expected {expected[i].ToString()} but got {input[i].ToString()}");
            }
            True(true);
        }
    }
}
