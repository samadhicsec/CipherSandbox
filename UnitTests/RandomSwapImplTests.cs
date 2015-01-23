using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using SwitchCipher;
using NSubstitute;

namespace UnitTests
{
    [TestClass]
    public class RandomSwapImplTests
    {
        [TestMethod]
        [ExpectedException(typeof(Exception), "A zero length input was allowed")]
        public void Test0LengthInput()
        {
            // Arrange
            byte[] input = new byte[0];
            RandomSwapImpl rsi = new RandomSwapImpl();
            
            // Act
            byte[] output = rsi.Swap(input, 0, input.Length);
            
            // Assert
        }

        [TestMethod]
        [ExpectedException(typeof(Exception), "An odd length input was allowed")]
        public void TestOddLengthInput()
        {
            // Arrange
            byte[] input = new byte[1];
            RandomSwapImpl rsi = new RandomSwapImpl();

            // Act
            byte[] output = rsi.Swap(input, 0, input.Length);

            // Assert
        }

        [TestMethod]
        public void TestNoSwap()
        {
            // Arrange
            byte[] input = new byte[10];
            (new RNGCryptoServiceProvider()).GetBytes(input);

            var _rng = Substitute.For<RandomNumberGenerator>();
            _rng.When(x => x.GetBytes(Arg.Any<byte[]>())).Do(x => ((byte[])x[0])[0] = 0);
            RandomSwapImpl rsi = new RandomSwapImpl(_rng);

            // Act
            byte[] output = rsi.Swap(input, 0, input.Length);

            // Assert
            CollectionAssert.AreEqual(input, output, "Input was " + Environment.NewLine + Helper.ByteArrayToString(input) + Environment.NewLine + "Output was" + Environment.NewLine + Helper.ByteArrayToString(output));
        }

        [TestMethod]
        public void TestSwap()
        {
            // Arrange
            byte[] input = new byte[10];
            (new RNGCryptoServiceProvider()).GetBytes(input);

            var _rng = Substitute.For<RandomNumberGenerator>();
            _rng.When(x => x.GetBytes(Arg.Any<byte[]>())).Do(x => ((byte[])x[0])[0] = 1);
            RandomSwapImpl rsi = new RandomSwapImpl(_rng);

            // Act
            byte[] output = rsi.Swap(input, 0, input.Length);

            byte[] input_firsthalf = new byte[input.Length / 2];
            byte[] input_secondhalf = new byte[input.Length / 2];
            Buffer.BlockCopy(input, 0, input_firsthalf, 0, input.Length / 2);
            Buffer.BlockCopy(input, input.Length / 2, input_secondhalf, 0, input.Length / 2);
            byte[] output_firsthalf = new byte[output.Length / 2];
            byte[] output_secondhalf = new byte[output.Length / 2];
            Buffer.BlockCopy(output, 0, output_firsthalf, 0, output.Length / 2);
            Buffer.BlockCopy(output, output.Length / 2, output_secondhalf, 0, output.Length / 2);

            // Assert
            CollectionAssert.AreEqual(input_firsthalf, output_secondhalf, "Input first half != Output second half.  Input was " + Environment.NewLine + Helper.ByteArrayToString(input) + Environment.NewLine + "Output was" + Environment.NewLine + Helper.ByteArrayToString(output));
            CollectionAssert.AreEqual(input_secondhalf, output_firsthalf, "Input second half != Output first half.  Input was " + Environment.NewLine + Helper.ByteArrayToString(input) + Environment.NewLine + "Output was" + Environment.NewLine + Helper.ByteArrayToString(output));
        }
    }
}
