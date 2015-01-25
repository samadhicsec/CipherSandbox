using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using Ciphers;

namespace UnitTests
{
    [TestClass]
    public class GuillotineCipherTest
    {
        [TestMethod]
        public void GuillotineCipherEncDecMsgLength1Test()
        {
            EncryptDecryptMsgLengthTest(1);
        }

        [TestMethod]
        public void GuillotineCipherEncDecMsgLength16Test()
        {
            EncryptDecryptMsgLengthTest(16);
        }

        [TestMethod]
        public void GuillotineCipherEncDecMsgLength256Test()
        {
            EncryptDecryptMsgLengthTest(256);
        }

        private void EncryptDecryptMsgLengthTest(int messageLength)
        {
            // Arrange
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            GuillotineCipher gc = new GuillotineCipher();

            byte[] authKey = new byte[16];
            rng.GetBytes(authKey);

            byte[] message = new byte[messageLength];
            rng.GetBytes(message);

            gc.Key = authKey;

            // Act
            byte[] ciphertext = new byte[0];
            byte[] plaintext = new byte[0];

            try
            {
                // Act
                ciphertext = gc.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
                plaintext = gc.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);

                // Assert
                CollectionAssert.AreEqual(message, plaintext,
                    "Message was " + Environment.NewLine + Helper.ByteArrayToString(message) + " (length=" + message.Length + ")" +
                    Environment.NewLine + "Ciphertext was " + Environment.NewLine + Helper.ByteArrayToString(ciphertext) + " (length=" + ciphertext.Length + ")" +
                    Environment.NewLine + "Plantext was" + Environment.NewLine + Helper.ByteArrayToString(plaintext) + " (length=" + plaintext.Length + ")");

            }
            catch (Exception e)
            {
                Assert.Fail("Exception: " + e.ToString() + Environment.NewLine +
                    "Message was " + Environment.NewLine + Helper.ByteArrayToString(message) + " (length=" + message.Length + ")" +
                    Environment.NewLine + "Ciphertext was " + Environment.NewLine + Helper.ByteArrayToString(ciphertext) + " (length=" + ciphertext.Length + ")" +
                    Environment.NewLine + "Plantext was" + Environment.NewLine + Helper.ByteArrayToString(plaintext) + " (length=" + plaintext.Length + ")");
            }
        }
    }
}
