using System;
using System.Linq;

namespace KybusEnigma.XUnit.Helper
{
    public class HexBin
    {
        public static byte[] Decode(string hex)
        {
            hex = hex.Replace(" ", "");
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static string Encode(byte[] hex)
        {
            return BitConverter.ToString(hex).Replace("-", "");
        }
    }
}
