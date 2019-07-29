using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace KybusEnigma.xUnit.Helper
{
    public class TestVectorContainer<TInputData, TInputExpected> : List<TestVector<TInputData, TInputExpected>>
    {
        Func<TInputData, byte[]> GetBytesOfData { get; }
        Func<TInputExpected, byte[]> GetBytesOfExpected { get; }

        public TestVectorContainer(Func<TInputData, byte[]> getBytesOfData, Func<TInputExpected, byte[]> getBytesOfExpected)
        {
            GetBytesOfData = getBytesOfData;
            GetBytesOfExpected = getBytesOfExpected;
        }

        public void Add(string title, TInputData data, TInputExpected expected) => this.Add(new TestVector<TInputData, TInputExpected>(title, GetBytesOfData, GetBytesOfExpected, data, expected));

        public (byte[] data, byte[] expected) Get(int index)
        {
            var item = this[index];
            return (item.Data, item.Expected);
        }

        public (byte[] data, byte[] expected) Get(string name)
        {
            var item = this.First(s => s.Name == name);
            return (item.Data, item.Expected);
        }
    }
}
