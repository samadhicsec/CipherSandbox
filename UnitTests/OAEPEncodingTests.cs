using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using Ciphers;

namespace UnitTests
{
    [TestClass]
    public class OAEPEncodingTests
    {
        [TestMethod]
        public void TestEncodeLength1()
        {
            // Arrange
            byte[] message = new byte[] { 0x01 };
            IAONT aont = new OAEPEncoding();

            // Act
            byte[] encodedMessage = aont.Encode(message);

            // Assert
            Assert.AreEqual<int>(message.Length + aont.seedSize, encodedMessage.Length);
        }

        [TestMethod]
        public void TestEncodeLength0()
        {
            // Arrange
            byte[] message = new byte[] { };
            IAONT aont = new OAEPEncoding();

            // Act
            byte[] encodedMessage = aont.Encode(message);

            // Assert
            Assert.AreEqual<int>(message.Length + aont.seedSize, encodedMessage.Length);
        }

        [TestMethod]
        public void TestEncodeLength1024()
        {
            // Arrange
            byte[] message = new byte[1024];
            IAONT aont = new OAEPEncoding();

            // Act
            byte[] encodedMessage = aont.Encode(message);

            // Assert
            Assert.AreEqual<int>(message.Length + aont.seedSize, encodedMessage.Length);
        }

        [TestMethod]
        public void TestDecodeLengthEqualsMessageLength()
        {
            // Arrange
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] message = new byte[1024];
            rng.GetBytes(message);

            // Act
            byte[] encodedMessage = (new OAEPEncoding()).Encode(message);
            byte[] decodedMessage = (new OAEPEncoding()).Decode(encodedMessage);

            // Assert
            Assert.AreEqual<int>(message.Length, decodedMessage.Length, "Message length = " + message.Length + ", decoded message length = " + decodedMessage.Length);
        }

        [TestMethod]
        public void TestEncodeDecode()
        {
            // Arrange
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] message = new byte[16];
            rng.GetBytes(message);
            //System.Diagnostics.Debug.WriteLine("Message = " + Helper.ByteArrayToString(message));
            
            // Act
            byte[] encodedMessage = (new OAEPEncoding()).Encode(message);
            byte[] decodedMessage = (new OAEPEncoding()).Decode(encodedMessage);
            //System.Diagnostics.Debug.WriteLine("Message = " + Helper.ByteArrayToString(message));
            // Assert
            CollectionAssert.AreEqual(message, decodedMessage, "Message was " + Environment.NewLine + Helper.ByteArrayToString(message) + Environment.NewLine + "Decoded message was" + Environment.NewLine + Helper.ByteArrayToString(decodedMessage));
        }
    }
}
