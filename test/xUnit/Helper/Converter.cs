using System;
using System.IO;
using System.Linq;
using System.Text;

namespace KybusEnigma.xUnit.Helper
{
    public class Converter
    {
        public static byte[] HexByteDecode(string hex)
        {
            hex = hex.Replace(" ", "");
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static string HexByteEncode(byte[] hex)
        {
            return BitConverter.ToString(hex).Replace("-", "");
        }

        public static byte[] Text2Bytes(string msg) => System.Text.Encoding.UTF8.GetBytes(msg);

        public static MemoryStream GenerateStreamFromString(string value) => new MemoryStream(Encoding.UTF8.GetBytes(value ?? ""));
    }
}
