using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using SwitchCipher;

namespace UnitTests
{
    [TestClass]
    public class SwitchOAEPTest
    {
        [TestMethod]
        public void EncryptDecryptEncMsgLength256Test()
        {
            IAONT aont = new OAEPEncoding();
            EncryptDecryptMsgLengthTest(256 - aont.seedSize);
        }

        [TestMethod]
        public void EncryptDecryptEncMsgLength257Test()
        {
            IAONT aont = new OAEPEncoding();
            EncryptDecryptMsgLengthTest(257 - aont.seedSize);
        }

        [TestMethod]
        public void EncryptDecryptEncMsgLength258Test()
        {
            IAONT aont = new OAEPEncoding();
            EncryptDecryptMsgLengthTest(258 - aont.seedSize);
        }

        [TestMethod]
        public void EncryptDecryptMsgLength256Test()
        {
            EncryptDecryptMsgLengthTest(256);
        }

        [TestMethod]
        public void EncryptDecryptMsgLength1Test()
        {
            EncryptDecryptMsgLengthTest(1);
        }

        [TestMethod]
        public void EncryptDecryptMsgLength2Test()
        {
            EncryptDecryptMsgLengthTest(2);
        }

        [TestMethod]
        public void EncryptDecryptMsgLength3Test()
        {
            EncryptDecryptMsgLengthTest(3);
        }

        private void EncryptDecryptMsgLengthTest(int messageLength)
        {
            // Arrange
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            SwitchCipher.SwitchOAEP sc = new SwitchCipher.SwitchOAEP();

            byte[] authKey = new byte[16];
            rng.GetBytes(authKey);

            byte[] message = new byte[messageLength];
            rng.GetBytes(message);

            sc.AuthenticationKey = authKey;

            // Act
            byte[] ciphertext = new byte[0];
            byte[] plaintext = new byte[0];

            try
            {
                // Act
                ciphertext = sc.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
                plaintext = sc.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                
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
