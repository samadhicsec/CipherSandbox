using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Ciphers
{
    /*
     * MACCipher is similiar to a symmetric cipher but instead of mixing a shared secret key to perform encryption, it calculates a randomised HMAC
     * on a bit of value 0 and then a bit of value 1, and writes to the ciphertext the first bit that differs between those HMACs of the HMAC for the
     * corresponding message bit.
     */
    public class MACCipher : SymmetricAlgorithm
    {
        protected KeyedHashAlgorithm moMAC;
        protected const int miSecurityFactor = 128;

        public MACCipher() : this(new HMACSHA256())
        {

        }

        public MACCipher(KeyedHashAlgorithm oMAC)
        {
            moMAC = oMAC;
            LegalKeySizesValue = new KeySizes[1];
            LegalKeySizesValue[0] = new KeySizes(128, 256, 128);
            BlockSizeValue = miSecurityFactor;   // The IV size has to be BlockSizeValue/8 for SymmetricAlgorithm.set_IV to work
            LegalBlockSizesValue = LegalKeySizesValue;
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new MACCipherDecrypt(moMAC, rgbKey, rgbIV);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new MACCipherEncrypt(moMAC, rgbKey, rgbIV);
        }

        public override void GenerateIV()
        {
            IVValue = new byte[miSecurityFactor / 8];
            (new RNGCryptoServiceProvider()).GetBytes(IVValue);
        }

        public override void GenerateKey()
        {
            KeyValue = new byte[miSecurityFactor / 8];
            (new RNGCryptoServiceProvider()).GetBytes(KeyValue);
        }

        //public override KeySizes[] LegalKeySizes
        //{
        //    get
        //    {
        //        return mKeySizes;
        //    }
        //}
    }

    public class MACCipherEncrypt : ICryptoTransform
    {
        byte[] mKey;
        byte[] mMACSeed;
        protected KeyedHashAlgorithm moMAC;

        public MACCipherEncrypt(KeyedHashAlgorithm oMAC, byte[] barrKey, byte[] barrIV)
        {
            moMAC = oMAC;
            mKey = barrKey;
            mMACSeed = barrIV;
        }

        bool ICryptoTransform.CanReuseTransform
        {
            get { return false; }
        }

        bool ICryptoTransform.CanTransformMultipleBlocks
        {
            get { return true; }
        }

        int ICryptoTransform.InputBlockSize
        {
            get { return 1; }
        }

        int ICryptoTransform.OutputBlockSize
        {
            get { return 1; }
        }

        int ICryptoTransform.TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            throw new NotImplementedException();
        }

        byte[] ICryptoTransform.TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            #region Validation
            // Make sure offset and count are positive
            if (inputOffset < 0)
            {
                // TODO
                throw new Exception("inputOffset < 0");
            }
            if (inputCount <= 0)
            {
                // TODO
                throw new Exception("inputCount <= 0");
            }

            // Make sure we are not trying to read outside the array.  Try to account for overflows as well.
            if ((inputBuffer.Length < inputOffset + inputCount) ||
                (inputOffset + inputCount < inputCount) ||
                (inputOffset + inputCount < inputOffset))
            {
                // TODO
                throw new IndexOutOfRangeException("Would read outside of array");
            }

            // Make sure inputCount does not exceed the max value of mMACindex
            if(inputCount*8 > Byte.MaxValue)
                throw new Exception("inputCount > " + Byte.MaxValue);

            #endregion
            // Allocate space for a buffer to calculate the HMAC on
            byte[] bufferHMAC = new byte[mMACSeed.Length + 1 + 1];    // We will HMAC the HMAC seed, the index and a bit

            // Allocate space for the ciphertext
            BitArray ciphertextBits = new BitArray(inputCount*8);

            // Looping at the byte level
            for(int i = 0; i < inputCount; i++)
            {
                // Copy 1 byte of the inputBuffer data to a BitArray
                byte[] messageByte = new byte[1];
                messageByte[0] = inputBuffer[inputOffset + i];
                BitArray messageBits = new BitArray(messageByte);
                             
                //Looping at the bit level
                for(int b = 0; b < messageBits.Length; b++)
                {
                    // Set the index
                    bufferHMAC[bufferHMAC.Length - 2] = (byte)(i * 8 + b);

                    // Calculate MACs of both possible values of the a bit
                    bufferHMAC[bufferHMAC.Length - 1] = 0xAA;   // Lets use bit pattern 10101010 as a zero
                    byte[] oMACZero = moMAC.ComputeHash(bufferHMAC);
                    bufferHMAC[bufferHMAC.Length - 1] = 0x55;   // Lets use bit pattern 01010101 as a one
                    byte[] oMACOne = moMAC.ComputeHash(bufferHMAC);

                    // Find the location of the first bit difference of the MACs
                    bool found = false;
                    for (byte j = 0; j < oMACZero.Length; j++)
                    {
                        if (oMACZero[j] != oMACOne[j])
                        {
                            for (byte k = 0; k < 8; k++)
                            {
                                Boolean bMACZeroBitValue = ((oMACZero[j] & ((byte)1 << k)) > 0);
                                Boolean bMACOneBitValue = ((oMACOne[j] & ((byte)1 << k)) > 0);
                                if (bMACZeroBitValue != bMACOneBitValue)
                                {
                                    // Record the value of the bit from MAC corresponding to the current bit value of the message
                                    if (messageBits[b])
                                        ciphertextBits[i * 8 + b] = bMACOneBitValue;
                                    else
                                        ciphertextBits[i * 8 + b] = bMACZeroBitValue;
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (found)
                            break;
                    }
                    if(!found)
                    {
                        // This means the HMACs were equal.  This is bad!  Or good if you like finding HMAC collisions.
                        throw new Exception("HMAC collision found for IV=" + BitConverter.ToString(mMACSeed) + " and index= " + (i * 8 + b));
                    }
                }
            }

            byte[] ciphertext = new byte[inputCount];
            ciphertextBits.CopyTo(ciphertext, 0);

            return ciphertext;
        }

        void IDisposable.Dispose()
        {
            
        }
    }

    public class MACCipherDecrypt : ICryptoTransform
    {
        byte[] mKey;
        byte[] mMACSeed;
        protected KeyedHashAlgorithm moMAC;
        
        public MACCipherDecrypt(KeyedHashAlgorithm oMAC, byte[] barrKey, byte[] barrIV)
        {
            moMAC = oMAC;
            mKey = barrKey;
            mMACSeed = barrIV;
        }

        bool ICryptoTransform.CanReuseTransform
        {
            get { return false; }
        }

        bool ICryptoTransform.CanTransformMultipleBlocks
        {
            get { return true; }
        }

        int ICryptoTransform.InputBlockSize
        {
            get { return 1; }
        }

        int ICryptoTransform.OutputBlockSize
        {
            get { return 1; }
        }

        int ICryptoTransform.TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            throw new NotImplementedException();
        }

        byte[] ICryptoTransform.TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            #region Validation
            // Make sure offset and count are positive
            if (inputOffset < 0)
            {
                // TODO
                throw new Exception("inputOffset < 0");
            }
            if (inputCount <= 0)
            {
                // TODO
                throw new Exception("inputCount <= 0");
            }

            // Make sure we are not trying to read outside the array.  Try to account for overflows as well.
            if ((inputBuffer.Length < inputOffset + inputCount) ||
                (inputOffset + inputCount < inputCount) ||
                (inputOffset + inputCount < inputOffset))
            {
                // TODO
                throw new IndexOutOfRangeException("Would read outside of array");
            }

            // Make sure inputCount does not exceed the max value of mMACindex
            if (inputCount * 8 > Byte.MaxValue)
                throw new Exception("inputCount > " + Byte.MaxValue);

            #endregion
            // Allocate space for a buffer to calculate the HMAC on
            byte[] bufferHMAC = new byte[mMACSeed.Length + 1 + 1];    // We will HMAC the HMAC seed, the index and a bit

            // Allocate space for the ciphertext
            BitArray plaintextBits = new BitArray(inputCount * 8);

            // Looping at the byte level
            for (int i = 0; i < inputCount; i++)
            {
                // Copy 1 byte of the inputBuffer data to a BitArray
                byte[] ciphertextByte = new byte[1];
                ciphertextByte[0] = inputBuffer[inputOffset + i];
                BitArray ciphertextBits = new BitArray(ciphertextByte);
                
                //Looping at the bit level
                for (int b = 0; b < ciphertextBits.Length; b++)
                {
                    // Set the index
                    bufferHMAC[bufferHMAC.Length - 2] = (byte)(i * 8 + b);

                    // Calculate MACs of both possible values of the a bit
                    bufferHMAC[bufferHMAC.Length - 1] = 0xAA;   // Lets use bit pattern 10101010 as a zero
                    byte[] oMACZero = moMAC.ComputeHash(bufferHMAC);
                    bufferHMAC[bufferHMAC.Length - 1] = 0x55;   // Lets use bit pattern 01010101 as a one
                    byte[] oMACOne = moMAC.ComputeHash(bufferHMAC);

                    // Find the location of the first bit difference of the MACs
                    bool found = false;
                    for (byte j = 0; j < oMACZero.Length; j++)
                    {
                        if (oMACZero[j] != oMACOne[j])
                        {
                            for (byte k = 0; k < 8; k++)
                            {
                                Boolean bMACZeroBitValue = ((oMACZero[j] & ((byte)1 << k)) > 0);
                                Boolean bMACOneBitValue = ((oMACOne[j] & ((byte)1 << k)) > 0);
                                if (bMACZeroBitValue != bMACOneBitValue)
                                {
                                    // The plaintext bit is the value of the MAC'd bit whose HMAC bit matches the ciphertext bit
                                    if (bMACOneBitValue == ciphertextBits[b])
                                        plaintextBits[i * 8 + b] = true;
                                    else
                                        plaintextBits[i * 8 + b] = false;
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (found)
                            break;
                    }
                    if (!found)
                    {
                        // This means the HMACs were equal.  This is bad!  Or good if you like finding HMAC collisions.
                        throw new Exception("HMAC collision found for IV=" + BitConverter.ToString(mMACSeed) + " and index= " + (i * 8 + b));
                    }
                }
            }

            byte[] plaintext = new byte[inputCount];
            plaintextBits.CopyTo(plaintext, 0);

            return plaintext;
        }

        void IDisposable.Dispose()
        {

        }
    }
}
