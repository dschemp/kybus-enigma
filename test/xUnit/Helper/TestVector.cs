using System;

namespace KybusEnigma.xUnit.Helper
{
    public class TestVector<TInputData, TOutputData, TInputExpected, TOutputExpected>
    {
        public string Name { get; }
        public TOutputData Data { get; }
        public TOutputExpected Expected { get; }

        public TestVector(string name, Func<TInputData, TOutputData> getBytesOfData, Func<TInputExpected, TOutputExpected> getBytesOfExpected, TInputData data, TInputExpected expected)
        {
            this.Name = name;

            Data = getBytesOfData(data);
            Expected = getBytesOfExpected(expected);
        }
    }
}
