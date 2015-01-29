using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Ciphers;

namespace UnitTests
{
    [TestClass]
    public class ValidateTests
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ArrayCountNegativeTest()
        {
            Validate.AnArray(new byte[1], 0, -2);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ArrayCountTooLargeTest()
        {
            Validate.AnArray(new byte[1], 0, 2);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ArrayOffsetNegativeTest()
        {
            Validate.AnArray(new byte[1], -2, 1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ArrayOffsetTooLargeTest()
        {
            Validate.AnArray(new byte[1], 2, 1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ArrayCombinedOffsetAndCountTooLargeTest()
        {
            Validate.AnArray(new byte[1], 1, 1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ArrayCombinedMaxOffsetAndCountOverflowTest()
        {
            Validate.AnArray(new byte[1], Int32.MaxValue, 1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ArrayCombinedOffsetAndMaxCountOverflowTest()
        {
            Validate.AnArray(new byte[1], 1, Int32.MaxValue);
        }
    }
}
