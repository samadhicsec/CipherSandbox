using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using Ciphers;

namespace CiphersTest
{
    class Program
    {
        static void Main(string[] args)
        {
            //TestGuillotineCipher();
            //TestMACCipher();
            //TestSwitchOAEP();

            //ProduceLengthCSVFile();
            ProduceLengthCSVFile2();
        }

        static void TestGuillotineCipher()
        {
            // Arrange
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            byte[] authKey = new byte[16];
            rng.GetBytes(authKey);

            byte[] message = new byte[16];
            rng.GetBytes(message);
            Console.WriteLine("Message was " + Environment.NewLine + ByteArrayToString(message) + " (length=" + message.Length + ")");

            GuillotineCipher mc = new GuillotineCipher();
            mc.Key = authKey;

            // Act
            byte[] ciphertext = mc.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
            Console.WriteLine("Ciphertext was" + Environment.NewLine + ByteArrayToString(ciphertext) + " (length=" + ciphertext.Length + ")");
            //Console.WriteLine("Ciphertext was ");
            //Console.WriteLine("Etm: " + ByteArrayToString(ciphertext, 0, 32));
            //Console.WriteLine("MAC seed: " + ByteArrayToString(ciphertext, 32, 16));
            //Console.WriteLine("MAC bits: " + ByteArrayToString(ciphertext, 48, 16));
            //Console.WriteLine("Swapped Encoded Msg: " + ByteArrayToString(ciphertext, 64, ciphertext.Length - 64));
            //Console.WriteLine("Ciphertext length: " + ciphertext.Length);
            byte[] plaintext = mc.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            Console.WriteLine("Plantext was" + Environment.NewLine + ByteArrayToString(plaintext) + " (length=" + plaintext.Length + ")");

            bool equal = plaintext.SequenceEqual(message);
            Console.WriteLine(Environment.NewLine + "Plaintext " + (equal ? "was" : "was NOT") + " equal to the message");
        }

        static void TestMACCipher()
        {
            // Arrange
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            byte[] authKey = new byte[16];
            rng.GetBytes(authKey);

            byte[] macSeed = new byte[16];
            rng.GetBytes(macSeed);

            byte[] message = new byte[1];
            rng.GetBytes(message);
            Console.WriteLine("Message was " + Environment.NewLine + ByteArrayToString(message) + " (length=" + message.Length + ")");

            MACCipher mc = new MACCipher();
            mc.Key = authKey;
            mc.IV = macSeed;

            // Act
            byte[] ciphertext = mc.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
            Console.WriteLine("Ciphertext was" + Environment.NewLine + ByteArrayToString(ciphertext) + " (length=" + ciphertext.Length + ")");
            //Console.WriteLine("Ciphertext was ");
            //Console.WriteLine("Etm: " + ByteArrayToString(ciphertext, 0, 32));
            //Console.WriteLine("MAC seed: " + ByteArrayToString(ciphertext, 32, 16));
            //Console.WriteLine("MAC bits: " + ByteArrayToString(ciphertext, 48, 16));
            //Console.WriteLine("Swapped Encoded Msg: " + ByteArrayToString(ciphertext, 64, ciphertext.Length - 64));
            //Console.WriteLine("Ciphertext length: " + ciphertext.Length);
            byte[] plaintext = mc.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            Console.WriteLine("Plantext was" + Environment.NewLine + ByteArrayToString(plaintext) + " (length=" + plaintext.Length + ")");

            bool equal = plaintext.SequenceEqual(message);
            Console.WriteLine(Environment.NewLine + "Plaintext " + (equal ? "was" : "was NOT") + " equal to the message");
        }

        static void TestSwitchOAEP()
        {
            // Arrange
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            
            byte[] authKey = new byte[16];
            rng.GetBytes(authKey);

            byte[] message = new byte[1];
            rng.GetBytes(message);
            Console.WriteLine("Message was " + Environment.NewLine + ByteArrayToString(message) + " (length=" + message.Length + ")");

            SwitchOAEP sc = new SwitchOAEP();
            sc.AuthenticationKey = authKey;

            // Act
            byte[] ciphertext = sc.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
            Console.WriteLine("Ciphertext was ");
            Console.WriteLine("Etm: " + ByteArrayToString(ciphertext, 0, 32));
            Console.WriteLine("MAC seed: " + ByteArrayToString(ciphertext, 32, 16));
            Console.WriteLine("MAC bits: " + ByteArrayToString(ciphertext, 48, 16));
            Console.WriteLine("Swapped Encoded Msg: " + ByteArrayToString(ciphertext, 64, ciphertext.Length - 64));
            Console.WriteLine("Ciphertext length: " + ciphertext.Length);
            byte[] plaintext = sc.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            Console.WriteLine("Plantext was" + Environment.NewLine + ByteArrayToString(plaintext) + " (length=" + plaintext.Length + ")");

            bool equal = plaintext.SequenceEqual(message);
            Console.WriteLine(Environment.NewLine + "Plaintext " + (equal ? "was" : "was NOT") + " equal to the message");
        }

        public static string ByteArrayToString(byte[] ba)
        {
            string hex = BitConverter.ToString(ba);
            return hex.Replace("-", "");
        }

        public static string ByteArrayToString(byte[] ba, int startIndex, int length)
        {
            string hex = BitConverter.ToString(ba, startIndex, length);
            return hex.Replace("-", "");
        }

        static void ProduceLengthCSVFile()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            SwitchOAEP sc = new SwitchOAEP();
            AesManaged aes128 = new AesManaged();
            aes128.KeySize = 128;
            aes128.BlockSize = 128;
            aes128.GenerateIV();
            aes128.GenerateKey();
            RijndaelManaged rijndael256 = new RijndaelManaged();
            rijndael256.KeySize = 256;
            rijndael256.BlockSize = 256;
            rijndael256.GenerateIV();
            rijndael256.GenerateKey();
            
            //int[] lengths = new int[] { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
            //int[] lengths = new int[] { 10, 100, 1000, 10000, 100000, 1000000, 1000001 };
            int x = 256;
            int[] lengths = new int[] { x - 1, x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7, x + 8, x + 9, x + 10, x + 11, x + 12, x + 13, x + 14, x + 15, x + 16 };

            string SwitchOAEPInputOutputLengths = "Message Length, SwitchOAEP Ciphertext Length, AES128 Ciphertext Length, RIJ256 Ciphertext Length" + Environment.NewLine;

            for (int i = 0; i < lengths.Length; i++)
            {
                // Create message of appropriate length
                byte[] message = new byte[lengths[i]];
                rng.GetBytes(message);

                byte[] ciphertextSwitchOAEP = sc.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
                byte[] ciphertextAes128 = aes128.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
                byte[] ciphertextAes256 = rijndael256.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);

                string output = message.Length + "," + ciphertextSwitchOAEP.Length + "," + (aes128.IV.Length + ciphertextAes128.Length + 32) + "," + (rijndael256.IV.Length + ciphertextAes256.Length + 32);
                Console.WriteLine(output);
                SwitchOAEPInputOutputLengths += output + Environment.NewLine;
            }

            File.WriteAllText("CipherLengths.csv", SwitchOAEPInputOutputLengths);

        }

        static void ProduceLengthCSVFile2()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            SwitchOAEP sc = new SwitchOAEP();
            GuillotineCipher gc = new GuillotineCipher();
            AesManaged aes128 = new AesManaged();
            aes128.KeySize = 128;
            aes128.BlockSize = 128;
            aes128.GenerateIV();
            aes128.GenerateKey();
            
            //int[] lengths = new int[] { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
            //int[] lengths = new int[] { 10, 100, 1000, 10000, 100000, 1000000, 1000001 };
            int x = 256;
            int[] lengths = new int[] { x - 1, x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7, x + 8, x + 9, x + 10, x + 11, x + 12, x + 13, x + 14, x + 15, x + 16 };

            string SwitchOAEPInputOutputLengths = "Message Length, SwitchOAEP Ciphertext Length, AES128 Ciphertext Length, Guillotine Ciphertext Length" + Environment.NewLine;

            for (int i = 0; i < lengths.Length; i++)
            {
                // Create message of appropriate length
                byte[] message = new byte[lengths[i]];
                rng.GetBytes(message);

                byte[] ciphertextSwitchOAEP = sc.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
                byte[] ciphertextAes128 = aes128.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);
                byte[] ciphertextGuillotine = gc.CreateEncryptor().TransformFinalBlock(message, 0, message.Length);

                string output = message.Length + "," + ciphertextSwitchOAEP.Length + "," + (aes128.IV.Length + ciphertextAes128.Length + 32) + "," + ciphertextGuillotine.Length;
                Console.WriteLine(output);
                SwitchOAEPInputOutputLengths += output + Environment.NewLine;
            }

            File.WriteAllText("CipherLengths.csv", SwitchOAEPInputOutputLengths);

        }
    }
}
