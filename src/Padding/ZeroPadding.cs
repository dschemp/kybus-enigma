﻿using System;
using System.Collections.Generic;
using System.Text;

namespace KybusEnigma.Lib.Padding
{
    public static class ZeroPadding
    {
        public static byte[] PadToSize(byte[] buffer, long size)
        {
            var bufferLength = buffer.GetLongLength(0);
            if (size < bufferLength)
                throw new ArgumentOutOfRangeException("Padding size cannot be smaller than input buffer size!");
            else if (size == bufferLength)
                return buffer;

            var newBuffer = new byte[size];
            Array.Copy(buffer, 0, newBuffer, 0, bufferLength);

            // For safety
            for (long i = bufferLength; i < size; i++)
                newBuffer[i] = 0x00;

            return newBuffer;
        }
    }
}
