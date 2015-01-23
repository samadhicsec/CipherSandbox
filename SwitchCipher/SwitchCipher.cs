using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace SwitchCipher
{
    public class SwitchOAEP : SymmetricAlgorithm
    {
        protected IAONT moAONT;
        protected IRandomSwap moRandOrd;
        protected KeyedHashAlgorithm moMAC;
        protected bool mbAuthNSet = false;
        protected const int miTotalPairsCount = 128;

        public SwitchOAEP()
            : this(new HMACSHA256(), new OAEPEncoding(), new RandomSwapImpl())
        {

        }

        public SwitchOAEP(KeyedHashAlgorithm oMAC, IAONT oAONT, IRandomSwap oRandOrd)
        {
            moMAC = oMAC;
            moAONT = oAONT;
            moAONT.seedSize = miTotalPairsCount / 8;   // The seed size needn't be longer than the complexity due to swapping parts
            moRandOrd = oRandOrd;
        }

        public IAONT AONT { get { return moAONT; } set { if(value != null) moAONT = value; } }
        public IRandomSwap RandomSwap { get { return moRandOrd; } set { if (value != null) moRandOrd = value; } }
        public KeyedHashAlgorithm MAC { get { return moMAC; } set { if (value != null) moMAC = value; } }

        public byte[] AuthenticationKey
        {
            set { moMAC.Key = value; mbAuthNSet = true; }
            get
            {
                if (mbAuthNSet)
                    return moMAC.Key;
                else
                    return null;
            }
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return CreateDecryptor(null, null);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new SwitchCipherDecryptTranform(miTotalPairsCount, moMAC, moAONT, moRandOrd);
        }

        public override ICryptoTransform CreateEncryptor()
        {
            return CreateEncryptor(null, null);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new SwitchCipherEncryptTranform(miTotalPairsCount, moMAC, moAONT, moRandOrd);
        }

        public override void GenerateIV()
        {
            throw new NotImplementedException();
        }

        public override void GenerateKey()
        {
            throw new NotImplementedException();
        }
    }

    public abstract class SwitchCipherTranform
    {
        /*
         * Calculates the maximum part size to use.  Assumes encoded message length is even.
         */
        protected int getMaxPartSize(int encodedMessageLength, int totalPartCount)
        {
            if (encodedMessageLength % totalPartCount == 0)
                return encodedMessageLength / totalPartCount;

            return (encodedMessageLength / totalPartCount) + 1;
        }

        /*
         * We keep on using the max part size until the length of the remaining parts is a multiple of the number of remaining parts
         */
        protected int getNextPartSize(int encodedMessageLength, int offset, int processedPartCount, int totalPartCount)
        {
            if (processedPartCount < totalPartCount)
                if ((encodedMessageLength - offset) % (totalPartCount - processedPartCount) == 0)
                    return (encodedMessageLength - offset) / (totalPartCount - processedPartCount);
                else
                    return getMaxPartSize(encodedMessageLength, totalPartCount);
            return 0;
        }
    }

    public class SwitchCipherEncryptTranform : SwitchCipherTranform, ICryptoTransform
    {
        IAONT moAONT;
        IRandomSwap moRandOrd;
        KeyedHashAlgorithm moMAC;
        int miTotalPairsCount;

        public SwitchCipherEncryptTranform(int totalPairsCount, KeyedHashAlgorithm oMAC, IAONT oAONT, IRandomSwap oRandOrd)
        {
            moMAC = oMAC;
            moAONT = oAONT;
            moRandOrd = oRandOrd;
            miTotalPairsCount = totalPairsCount;
        }

        public bool CanReuseTransform
        {
            get { return true; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return false; }
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
            #region Validation
            // Make sure offset and count are positive
            if (inputOffset < 0)
            {
                // TODO
                throw new Exception("inputOffset < 0");
            }
            if (inputCount < 0)
            {
                // TODO
                throw new Exception("inputCount < 0");
            }

            // Make sure we are not trying to read outside the array.  Try to account for overflows as well.
            if ((inputBuffer.Length < inputOffset + inputCount) ||
                (inputOffset + inputCount < inputCount) ||
                (inputOffset + inputCount < inputOffset) )
            {
                // TODO
                throw new Exception("would read outside of array");
            }

            //// Make sure the message is not empty.  If it is return an empty array.
            //if (inputBuffer.Length < inputOffset + inputCount)
            //{
            //    System.Diagnostics.Debug.WriteLine("Message was empty");
            //    return new byte[0];
            //}
            #endregion

            // Set the padding to always be 1 byte
            byte[] padding = new byte[] { 1 };
            // Increase the padding if the input if AONT message length isn't enough to create 1 byte parts
            if (moAONT.outputLengthForInputLength(inputCount) < (2 * miTotalPairsCount))
            {
                int paddingBytes = (2 * miTotalPairsCount) - moAONT.outputLengthForInputLength(inputCount);
                if (paddingBytes > 255)
                    throw new Exception("Unable to pad message as parameters have caused more than 255 padding bytes to be required");
                padding = new byte[paddingBytes];
                for (int i = 0; i < paddingBytes; i++)
                    padding[i] = (byte)paddingBytes;
            }


            // If the message length is odd, then set a flag to copy the last byte of AONT(m) straight to the ciphertext
            bool bMsgLengthOdd = false;
            if ((inputCount + padding.Length) % 2 != 0)
            {
                bMsgLengthOdd = true;
            }      
            
            // Copy the message + padding
            byte[] message = new byte[inputCount + padding.Length];
            Buffer.BlockCopy(inputBuffer, inputOffset, message, 0, inputCount);
            Buffer.BlockCopy(padding, 0, message, inputCount, padding.Length);

            // All Or Nothing Transform the message
            byte[] encodedMessage = moAONT.Encode(message);
            //string hex = BitConverter.ToString(encodedMessage);
            //Console.WriteLine("AONT Message: " + hex.Replace("-", "") + " (length = " + encodedMessage.Length + ")");

            // For an odd length message we will copy the last byte straight to the ciphertext, so for the purpose of processing we ignore this byte
            int encodedMessageLength = bMsgLengthOdd ? encodedMessage.Length - 1 : encodedMessage.Length;

            // Determine the size of each message part (except for perhaps the last
            int partSize = getMaxPartSize(encodedMessageLength, 2 * miTotalPairsCount);

            // Generate the MAC seed
            byte[] seedMAC = new byte[miTotalPairsCount / 8];
            (new RNGCryptoServiceProvider()).GetBytes(seedMAC);

            // Allocate space for a buffer to calculate the HMAC on
            byte[] bufferHMAC = new byte[seedMAC.Length + 1 + 2 * partSize];    // We will HMAC the HMAC seed, the index and the 2 parts

            // Copy the HMAC seed to the HMAC buffer
            Buffer.BlockCopy(seedMAC, 0, bufferHMAC, 0, seedMAC.Length);

            // Allocate space for the MAC bits
            byte[] bitsMAC = new byte[miTotalPairsCount / 8];

            // Allocate space for the ciphertext = Length of Encrypt-then MAC + HMAC seed + MAC bits + encoded message length
            byte[] ciphertext = new byte[moMAC.HashSize / 8 + seedMAC.Length + bitsMAC.Length + encodedMessageLength + (bMsgLengthOdd?1:0)];
            // For an odd length message copy the last encoded byte directly to the ciphertext
            if (bMsgLengthOdd)
                ciphertext[ciphertext.Length - 1] = encodedMessage[encodedMessage.Length - 1];

            // Note where to write the swapped parts
            int ciphertextOffset = moMAC.HashSize / 8 + seedMAC.Length + bitsMAC.Length;
            // Offset into the encodedMessage
            int offset = 0;

            for (int i = 0; i < miTotalPairsCount; i++)
            {
                bufferHMAC[seedMAC.Length] = (byte)i;
                // Make a copy of the 2 parts in the correct order
                Buffer.BlockCopy(encodedMessage, offset, bufferHMAC, seedMAC.Length + 1, 2 * partSize);
                // Calculate the MAC of the 2 parts in the correct order
                byte[] oMACUnswapped = moMAC.ComputeHash(bufferHMAC);
                // Make a copy of the 2 parts in the swapped order
                Buffer.BlockCopy(encodedMessage, offset + partSize, bufferHMAC, seedMAC.Length + 1, partSize);
                Buffer.BlockCopy(encodedMessage, offset, bufferHMAC, seedMAC.Length + 1 + partSize, partSize);
                // Calculate the MAC of the 2 parts in the swapped order
                byte[] oMACSwapped = moMAC.ComputeHash(bufferHMAC);

                // Find the location of the first bit difference of the MACs
                bool found = false;
                for(byte j = 0; j < oMACUnswapped.Length; j++)
                {
                    if (oMACSwapped[j] != oMACUnswapped[j])
                    {
                        for(byte k = 0; k < 8; k++)
                        {
                            Boolean bUnSwappedBitSet = ((oMACUnswapped[j] & ((byte)1 << k)) > 0);
                            Boolean bSwappedBitSet = ((oMACSwapped[j] & ((byte)1 << k)) > 0);
                            if(bUnSwappedBitSet != bSwappedBitSet)
                            {
                                // Record the value of the bit from the unswapped MAC
                                byte bitValue = bUnSwappedBitSet ? (byte)1 : (byte)0;
                                bitsMAC[i / 8] |= (byte)(bitValue << (7 - (i % 8)));
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
                    // Either the parts were identical, or we found a hash collision(!).  We allow this case under the assumption that it won't happen 
                    // very often and that although it reduces the overall security, it won't reduce it much.
                }

                // Copy to ciphertext
                Buffer.BlockCopy(moRandOrd.Swap(encodedMessage, offset, 2 * partSize), 0, ciphertext, ciphertextOffset, 2 * partSize);
                ciphertextOffset += (2 * partSize);

                offset += (2 * partSize);

                partSize = getNextPartSize(encodedMessageLength, offset, (i+1) * 2, 2 * miTotalPairsCount);

                // If the partSize changes we need to alter the size of bufferHMAC
                if (bufferHMAC.Length != (seedMAC.Length + 1 + 2 * partSize))
                    bufferHMAC = new byte[seedMAC.Length + 1 + 2 * partSize];
            }

            // Prepend the HMAC seed 
            Buffer.BlockCopy(seedMAC, 0, ciphertext, moMAC.HashSize / 8, seedMAC.Length);

            // Prepend the bits from the MACs 
            Buffer.BlockCopy(bitsMAC, 0, ciphertext, moMAC.HashSize / 8 + seedMAC.Length, bitsMAC.Length);

            // Prepend Encrypt-then-MAC construction to the beginning of the ciphertext
            byte[] EtM = moMAC.ComputeHash(ciphertext, moMAC.HashSize / 8, ciphertext.Length - (moMAC.HashSize / 8));
            Buffer.BlockCopy(EtM, 0, ciphertext, 0, EtM.Length);

            return ciphertext;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }

    public class SwitchCipherDecryptTranform : SwitchCipherTranform, ICryptoTransform
    {
        IAONT moAONT;
        IRandomSwap moRandOrd;
        KeyedHashAlgorithm moMAC;
        int miTotalPairsCount;

        public SwitchCipherDecryptTranform(int totalPairsCount, KeyedHashAlgorithm oMAC, IAONT oAONT, IRandomSwap oRandOrd)
        {
            moMAC = oMAC;
            moAONT = oAONT;
            moRandOrd = oRandOrd;
            miTotalPairsCount = totalPairsCount;
        }

        public bool CanReuseTransform
        {
            get { return true; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return false; }
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
            #region Validation
            // Make sure offset and count are positive
            if (inputOffset < 0)
            {
                // TODO
            }
            if (inputCount < 0)
            {
                // TODO
            }

            // Make sure we are not trying to read outside the array.  Try to account for overflows as well.
            if ((inputBuffer.Length < inputOffset + inputCount) ||
                (inputOffset + inputCount < inputCount) ||
                (inputOffset + inputCount < inputOffset))
            {
                // TODO
            }

            //// Make sure the ciphertext is not empty.  If it is return an empty array.
            //if (inputBuffer.Length == inputOffset + inputCount)
            //{
            //    return new byte[0];
            //}
            #endregion

            // Check the ciphertext is large enough, Encrypt-then-MAC sig + MAC bits + at least 2 * miTotalPairsCount bytes
            if (moMAC.HashSize / 8 + 2 * (miTotalPairsCount / 8) + (2 * miTotalPairsCount) > inputCount)
            {
                // TODO
                throw new Exception("Ciphertext too short");
            }

            // Extract the Encrypt-then-MAC signature
            byte[] EtM = new byte[moMAC.HashSize / 8];
            Buffer.BlockCopy(inputBuffer, inputOffset, EtM, 0, EtM.Length);
            // Calculate the Encrypt-then-MAC signature
            byte[] calcEtM = moMAC.ComputeHash(inputBuffer, inputOffset + EtM.Length, inputCount - EtM.Length);
            // Compare
            if(!calcEtM.SequenceEqual(EtM))
            {
                // Throw not authenticated exception
                throw new Exception("Authentication check failed");
            }

            // Extract the HMAC seed
            byte[] seedMAC = new byte[miTotalPairsCount / 8];
            Buffer.BlockCopy(inputBuffer, inputOffset + EtM.Length, seedMAC, 0, seedMAC.Length);

            // Extract the MAC bits
            byte[] bitsMAC = new byte[miTotalPairsCount / 8];
            Buffer.BlockCopy(inputBuffer, inputOffset + EtM.Length + seedMAC.Length, bitsMAC, 0, bitsMAC.Length);

            // Allocate space for the encodedMessage
            byte[] encodedMessage = new byte[inputCount - EtM.Length - seedMAC.Length - bitsMAC.Length];

            // If the encodedMessage is odd in length copy the last byte from the ciphertext to the encodedMessage
            int encodedMessageLength = encodedMessage.Length;
            if( encodedMessage.Length % 2 != 0)
            {
                encodedMessage[encodedMessage.Length - 1] = inputBuffer[inputOffset + (inputCount - 1)];
                encodedMessageLength = encodedMessage.Length - 1;
            }

            // Determine the size of each message part (except for perhaps the last
            int partSize = getMaxPartSize(encodedMessageLength, 2 * miTotalPairsCount);

            // Allocate space for a buffer to calculate the HMAC on
            byte[] bufferHMAC = new byte[seedMAC.Length + 1 + 2 * partSize];    // We will HMAC the HMAC seed, the index and the 2 parts

            // Copy the HMAC seed to the HMAC buffer
            Buffer.BlockCopy(seedMAC, 0, bufferHMAC, 0, seedMAC.Length);

            int offset = 0;     //  Offset into the where we are writing the unswapped encoded message
            int encodedMsgOffset = inputOffset + EtM.Length + seedMAC.Length + bitsMAC.Length;  // Offset into inputBuffer to read the swapped encoded message

            for (int i = 0; i < miTotalPairsCount; i++)
            {
                bufferHMAC[seedMAC.Length] = (byte)i;
                // Calculate the MAC of the 2 parts, unswapped and swapped
                // 1st unswapped
                Buffer.BlockCopy(inputBuffer, encodedMsgOffset, bufferHMAC, seedMAC.Length + 1, 2 * partSize);
                byte[] oMACUnswapped = moMAC.ComputeHash(bufferHMAC);
                // then swapped
                Buffer.BlockCopy(inputBuffer, encodedMsgOffset, bufferHMAC, seedMAC.Length + 1 + partSize, partSize);
                Buffer.BlockCopy(inputBuffer, encodedMsgOffset + partSize, bufferHMAC, seedMAC.Length + 1, partSize);
                byte[] oMACSwapped = moMAC.ComputeHash(bufferHMAC);

                // Find the location of the first bit difference
                bool bFound = false;
                byte[] correctPair = new byte[2 * partSize];
                for (byte j = 0; j < oMACUnswapped.Length; j++)
                {
                    if (oMACSwapped[j] != oMACUnswapped[j])
                    {
                        for (byte k = 0; k < 8; k++)
                        {
                            Boolean bUnSwappedBitSet = ((oMACUnswapped[j] & ((byte)1 << k)) > 0);
                            Boolean bSwappedBitSet = ((oMACSwapped[j] & ((byte)1 << k)) > 0);
                            if (bUnSwappedBitSet != bSwappedBitSet)
                            {
                                // Get the value of the bit
                                byte bitValue = (byte)((bitsMAC[i / 8] >> (7 - (i % 8))) & 1);
                                if ((bitValue == 1) == bUnSwappedBitSet)
                                    Buffer.BlockCopy(inputBuffer, encodedMsgOffset, correctPair, 0, 2 * partSize);
                                else if ((bitValue == 1) == bSwappedBitSet)
                                {
                                    Buffer.BlockCopy(inputBuffer, encodedMsgOffset + partSize, correctPair, 0, partSize);
                                    Buffer.BlockCopy(inputBuffer, encodedMsgOffset, correctPair, partSize, partSize);
                                }
                                bFound = true;
                                break;
                            }
                        }
                    }
                    if (bFound)
                        break;
                }
                if (!bFound)
                {
                    // Likely the parts are identical, so swapping then and calculating the hash yields the same hash.
                    // Just set the unswapped version
                    Buffer.BlockCopy(inputBuffer, encodedMsgOffset, correctPair, 0, 2 * partSize);
                }

                // Copy to correctly ordered pair to the encoded message
                Buffer.BlockCopy(correctPair, 0, encodedMessage, offset, 2 * partSize);
                offset += (2 * partSize);

                encodedMsgOffset += (2 * partSize);

                partSize = getNextPartSize(encodedMessageLength, offset, (i + 1) * 2, 256);

                // If the partSize changes we need to alter the size of bufferHMAC
                if (bufferHMAC.Length != (seedMAC.Length + 1 + 2 * partSize))
                    bufferHMAC = new byte[seedMAC.Length + 1 + 2 * partSize];
            }
            
            // Reverse All Or Nothing Transform the message
            byte[] paddedMessage = moAONT.Decode(encodedMessage);
            //string hex = BitConverter.ToString(encodedMessage);
            //Console.WriteLine("Deco Message: " + hex.Replace("-", "") + " (length = " + encodedMessage.Length + ")");

            // Remove padding
            int paddingBytes = paddedMessage[paddedMessage.Length - 1];
            // Check all the padding bytes are correct
            for (int i = 0; i < paddingBytes; i++)
            {
                if (paddedMessage[paddedMessage.Length - 1 - i] != paddingBytes)
                    throw new Exception("Padding error found");
            }
            byte[] message = new byte[paddedMessage.Length - paddingBytes];
            Buffer.BlockCopy(paddedMessage, 0, message, 0, message.Length);

            return message;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }

}