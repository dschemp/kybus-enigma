using System;
using NUnit.Framework;

namespace Kybus.Enigma.Tests.Helper
{
    internal static class CustomAssert
    {
        public static void MatchArrays<T>(T[] input, T[] expected) where T : IComparable
        {
            if (input.Length != expected.Length)
                Assert.Fail();

            for (var i = 0; i < input.Length; i++)
            {
                Assert.That(input[i], Is.EqualTo(expected[i]));
            }
        }
    }
}
