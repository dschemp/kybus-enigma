using System;
using System.Collections.Generic;
using System.Linq;

namespace KybusEnigma.xUnit.Helper
{
    public class TestVectorContainer<TInputData, TOutputData, TInputExpected, TOutputExpected> : List<TestVector<TInputData, TOutputData, TInputExpected, TOutputExpected>>
    {
        Func<TInputData, TOutputData> GetBytesOfData { get; }
        Func<TInputExpected, TOutputExpected> GetBytesOfExpected { get; }

        public TestVectorContainer(Func<TInputData, TOutputData> getBytesOfData, Func<TInputExpected, TOutputExpected> getBytesOfExpected)
        {
            GetBytesOfData = getBytesOfData;
            GetBytesOfExpected = getBytesOfExpected;
        }

        public void Add(string title, TInputData data, TInputExpected expected) => this.Add(new TestVector<TInputData, TOutputData, TInputExpected, TOutputExpected>(title, GetBytesOfData, GetBytesOfExpected, data, expected));
        public void Add(TInputData data, TInputExpected expected) => this.Add(new TestVector<TInputData, TOutputData, TInputExpected, TOutputExpected>(null, GetBytesOfData, GetBytesOfExpected, data, expected));

        public (TOutputData data, TOutputExpected expected) Get(int index)
        {
            var item = this.ElementAt(index);
            return (item.Data, item.Expected);
        }

        public (TOutputData data, TOutputExpected expected) Get(string name)
        {
            var item = this.First(s => s.Name == name);
            return (item.Data, item.Expected);
        }

        public (TOutputData, TOutputExpected) this[string name]
        {
            get => Get(name);
        }

        public new (TOutputData, TOutputExpected) this[int idx] => Get(idx);
    }
}
