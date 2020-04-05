namespace Kybus.Enigma.Encryption.Symmetric
{
    internal static class AesExtensions
    {
        public static void ApplyXorTo(this byte[] plainText, byte[] data)
        {
            for (int i = 0; i < 16; i++)
            {
                plainText[i] ^= data[i];
            }
        }

        public static byte[,] ConvertArrayToState(this byte[] arr)
        {
            byte[,] state = new byte[4, 4];

            // Befuelt das State Array aus dem Data Byte Array
            for (int i = 0; i < 16; i++)
            {
                int x = i / 4;
                int y = i % 4;

                state[x, y] = arr[i];
            }

            return state;
        }

        public static byte[] ConvertStateToByteArray(this byte[,] state)
        {
            if (state == null)
            {
                return null;
            }

            byte[] bytes = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                int x = i / 4;
                int y = i % 4;

                bytes[i] = state[x, y];
            }

            return bytes;
        }

        public static byte[,] DeepCopyStateArray(this byte[,] state)
        {
            return (byte[,])state.Clone();
        }
    }
}