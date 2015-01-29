using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Ciphers
{
    public class GuillotineCipher : SymmetricAlgorithm
    {
        protected KeyedHashAlgorithm moMAC;
        protected SymmetricAlgorithm moCipher;
        protected IAONT moAONT;
        protected const int miSecurityFactor = 128;

        public GuillotineCipher() : this(new HMACSHA256(), new MACCipher(), new OAEPEncoding())
        {

        }

        public GuillotineCipher(KeyedHashAlgorithm oMAC, SymmetricAlgorithm oCipher, IAONT oAONT)
        {
            moMAC = oMAC;
            moCipher = oCipher;
            moAONT = oAONT;
            LegalKeySizesValue = new KeySizes[1];
            LegalKeySizesValue[0] = new KeySizes(128, 256, 128);
            BlockSizeValue = miSecurityFactor;   // The IV size has to be BlockSizeValue/8 for SymmetricAlgorithm.set_IV to work
            LegalBlockSizesValue = new KeySizes[1];
            LegalBlockSizesValue[0] = new KeySizes(miSecurityFactor, miSecurityFactor, 0);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new GuillotineCipherDecrypt(moMAC, moCipher, moAONT, rgbKey);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new GuillotineCipherEncrypt(moMAC, moCipher, moAONT, rgbKey);
        }

        public override void GenerateIV()
        {
            IVValue = new byte[0];
        }

        public override void GenerateKey()
        {
            KeyValue = new byte[miSecurityFactor / 8];
            (new RNGCryptoServiceProvider()).GetBytes(KeyValue);
        }
    }

    public class GuillotineCipherEncrypt : ICryptoTransform
    {
        byte[] mKey;
        protected KeyedHashAlgorithm moMAC;
        protected SymmetricAlgorithm moCipher;
        protected IAONT moAONT;

        public GuillotineCipherEncrypt(KeyedHashAlgorithm oMAC, SymmetricAlgorithm oCipher, IAONT oAONT, byte[] barrKey)
        {
            moMAC = oMAC;
            moCipher = oCipher;
            moAONT = oAONT;
            mKey = barrKey;
        }

        public bool CanReuseTransform
        {
            get { throw new NotImplementedException(); }
        }

        public bool CanTransformMultipleBlocks
        {
            get { throw new NotImplementedException(); }
        }

        public int InputBlockSize
        {
            get { throw new NotImplementedException(); }
        }

        public int OutputBlockSize
        {
            get { throw new NotImplementedException(); }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            throw new NotImplementedException();
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            Validate.AnArray(inputBuffer, inputOffset, inputCount);

            // AONT the message
            byte[] messageAONT = moAONT.Encode(inputBuffer, inputOffset, inputCount);

            // Get MAC of the output of the AONT
            byte[] macMessageAONT = moMAC.ComputeHash(messageAONT);

            // Encrypt the head of the AONT message using the Symmetric Cipher
            moCipher.BlockSize = macMessageAONT.Length * 8;
            moCipher.IV = macMessageAONT;
            byte[] cipheredHeadOfMessageAONT = moCipher.CreateEncryptor().TransformFinalBlock(messageAONT, 0, mKey.Length);
            // Replace the head of the AONT message with the encrypted head
            Buffer.BlockCopy(cipheredHeadOfMessageAONT, 0, messageAONT, 0, cipheredHeadOfMessageAONT.Length);

            // Copy the MAC and ciphered data to the ciphertext
            byte[] ciphertext = new byte[macMessageAONT.Length + messageAONT.Length];
            Buffer.BlockCopy(macMessageAONT, 0, ciphertext, 0, macMessageAONT.Length);
            Buffer.BlockCopy(messageAONT, 0, ciphertext, macMessageAONT.Length, messageAONT.Length);

            return ciphertext;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }

    public class GuillotineCipherDecrypt : ICryptoTransform
    {
        byte[] mKey;
        protected KeyedHashAlgorithm moMAC;
        protected SymmetricAlgorithm moCipher;
        protected IAONT moAONT;

        public GuillotineCipherDecrypt(KeyedHashAlgorithm oMAC, SymmetricAlgorithm oCipher, IAONT oAONT, byte[] barrKey)
        {
            moMAC = oMAC;
            moCipher = oCipher;
            moAONT = oAONT;
            mKey = barrKey;
        }

        public bool CanReuseTransform
        {
            get { throw new NotImplementedException(); }
        }

        public bool CanTransformMultipleBlocks
        {
            get { throw new NotImplementedException(); }
        }

        public int InputBlockSize
        {
            get { throw new NotImplementedException(); }
        }

        public int OutputBlockSize
        {
            get { throw new NotImplementedException(); }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            throw new NotImplementedException();
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            Validate.AnArray(inputBuffer, inputOffset, inputCount);

            // Extract the MAC and ciphered from the input
            byte[] macMessageAONT = new byte[moMAC.HashSize / 8];
            byte[] messageAONT = new byte[inputCount - macMessageAONT.Length];
            Buffer.BlockCopy(inputBuffer, inputOffset, macMessageAONT, 0, macMessageAONT.Length);
            Buffer.BlockCopy(inputBuffer, inputOffset + macMessageAONT.Length, messageAONT, 0, messageAONT.Length);

            // Decrypt the head of the AONT message
            byte[] plaintextHeadOfMessageAONT = moCipher.CreateDecryptor().TransformFinalBlock(messageAONT, 0, mKey.Length);

            // Replace the encrypted head with the plaintext head
            Buffer.BlockCopy(plaintextHeadOfMessageAONT, 0, messageAONT, 0, plaintextHeadOfMessageAONT.Length);

            // Verify the MAC of the AONT message
            byte[] calcMacMessageAONT = moMAC.ComputeHash(messageAONT);
            if (!calcMacMessageAONT.SequenceEqual(macMessageAONT))
            {
                // Throw not authenticated exception
                throw new Exception("Authentication check failed");
            }

            // Inverse the AONT of the AONT message
            byte[] plaintext = moAONT.Decode(messageAONT, 0, messageAONT.Length);

            return plaintext;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
