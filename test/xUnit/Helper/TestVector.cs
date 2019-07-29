using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Text;

namespace KybusEnigma.xUnit.Helper
{
    public class TestVector<TInputData, TInputExpected>
    {
        public string Name { get; }
        private Func<TInputData, byte[]> GetBytesOfData { get; }
        private Func<TInputExpected, byte[]> GetBytesOfExpected { get; }

        public byte[] Data { get; }
        public byte[] Expected { get; }

        public TestVector(string name, Func<TInputData, byte[]> getBytesOfData, Func<TInputExpected, byte[]> getBytesOfExpected, TInputData data, TInputExpected expected)
        {
            this.Name = name;
            GetBytesOfData = getBytesOfData;
            GetBytesOfExpected = getBytesOfExpected;

            Data = GetBytesOfData(data);
            Expected = getBytesOfExpected(expected);
        }
    }
}
