using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Ciphers
{
    public class OAEPEncoding : IAONT
    {
        int mSeedSize = 16;
        byte[] mSeed;

        /*
         * The length in bytes of the seed to use.  Default is 16.
         */ 
        public int seedSize
        {
            get { return mSeedSize; }
            set
            {
                if (value > 0)
                    mSeedSize = value;
            }
        }

        /*
         * The seed used to encode the message
         */
        public byte[] Seed
        {
            get
            {
                return mSeed;
            }
            set
            {
                if (value.Length != mSeedSize)
                    throw new Exception("Cannot set Seed, the value's size is different to seedSize");
                mSeed = (byte[])value.Clone();
            }
        }

        /*
         * Returns the output length in bytes of the encoded message if the input length of the message is inputLength bytes
         */ 
        public int outputLengthForInputLength(int inputLength)
        {
            return mSeedSize + inputLength;
        }

        public byte[] Encode(byte[] message)
        {
            return Encode(message, 0, message.Length);
        }

        public byte[] Encode(byte[] message, int messageOffset, int messageCount)
        {
            PKCS1MaskGenerationMethod mgf = new PKCS1MaskGenerationMethod();
            // The default hash is SHA1, so lets change that to something people will feel more confortable with
            mgf.HashName = "SHA256";
            return Encode(new SHA256CryptoServiceProvider(), mgf, new RNGCryptoServiceProvider(), message, messageOffset, messageCount);
        }

        public byte[] Decode(byte[] encodedMessage)
        {
            return Decode(encodedMessage, 0, encodedMessage.Length);
        }

        public byte[] Decode(byte[] encodedMessage, int encodedMessageOffset, int encodedMessageCount)
        {
            PKCS1MaskGenerationMethod mgf = new PKCS1MaskGenerationMethod();
            // The default hash is SHA1, so lets change that to something people will feel more confortable with
            mgf.HashName = "SHA256";
            return Decode(new SHA256CryptoServiceProvider(), mgf, encodedMessage, encodedMessageOffset, encodedMessageCount);
        }

        public byte[] Encode(HashAlgorithm hash, PKCS1MaskGenerationMethod mgf, RandomNumberGenerator rng, byte[] data, int dataOffset, int dataCount)
        {
            Validate.AnArray(data, dataOffset, dataCount);

            //int lHash = hash.HashSize / 8;
            int lEM = mSeedSize + data.Length;
            //System.Diagnostics.Debug.WriteLine("Data was " + ByteArrayToString(data));
            // Inspired by RFC3447 https://www.ietf.org/rfc/rfc3447.txt, from 7.1.1, step 2
            // BUT THIS IMPLEMENTATION IS NOT COMPLIANT WITH THE STANDARD!!!
            // I have removed the static hash (PS) and static bytes

            // a. Not putting the hash of the label in the encoding
            //hash.ComputeHash(new byte[0]);
            ////byte[] DB = new byte[lEM - lHash];
            //byte[] DB = new byte[lHash + 1 + data.Length];
            byte[] DB = new byte[dataCount];
            Buffer.BlockCopy(data, dataOffset, DB, 0, dataCount);

            // b. No need to calculate PS as we will always choose lengths so it is zero

            // c. Concatenate lHash, PS, 0x01, data.  For this impl nothing to copy
            //Buffer.InternalBlockCopy(hash.Hash, 0, DB, 0, lHash);
            ////DB[DB.Length - data.Length - 1] = 1;
            //DB[lHash + 1] = 1;
            ////Buffer.InternalBlockCopy(data, 0, DB, DB.Length - data.Length, data.Length);
            //Buffer.InternalBlockCopy(data, 0, DB, (lHash + 1) + 1, data.Length);
                        
            // d.  Generate random seed.
            // Another departure from the RFC, we'll let the seed size be different from the hash size.
            if (null == mSeed)
            {
                mSeed =new byte[mSeedSize];
                rng.GetBytes(mSeed);
            }
            
            //System.Diagnostics.Debug.WriteLine("Seed was " + ByteArrayToString(seed));
            // e.  Create dbMask
            byte[] dbMask = mgf.GenerateMask(mSeed, DB.Length);
            // f. Mask DB
            for (int i = 0; i < DB.Length; i++)
            {
                DB[i] ^= dbMask[i];
            }
            // g. Create seedMask
            byte[] seedMask = mgf.GenerateMask(DB, mSeedSize);
            // h. Mask the seed and create maskedSeed
            byte[] maskedSeed = (byte[])mSeed.Clone();
            for (int j = 0; j < maskedSeed.Length; j++)
            {
                maskedSeed[j] ^= seedMask[j];
            }
            // i. Create the encoded message EM
            byte[] EM = new byte[lEM];
            Buffer.BlockCopy(maskedSeed, 0, EM, 0, maskedSeed.Length);
            Buffer.BlockCopy(DB, 0, EM, maskedSeed.Length, DB.Length);

            return EM;
        }

        public byte[] Decode(HashAlgorithm hash, PKCS1MaskGenerationMethod mgf, byte[] encodedData, int encodedDataOffset, int encodedDataCount)
        {
            Validate.AnArray(encodedData, encodedDataOffset, encodedDataCount);

            if (encodedDataCount < mSeedSize)
            {
                // TODO throw an exception
                throw new Exception("encodedData is not long enough (" + encodedDataCount + " bytes) as the seed is " + mSeedSize + " bytes");
            }

            byte[] maskedSeed = new byte[mSeedSize];
            byte[] maskedDB = new byte[encodedDataCount - mSeedSize];
            Buffer.BlockCopy(encodedData, encodedDataOffset, maskedSeed, 0, maskedSeed.Length);
            Buffer.BlockCopy(encodedData, encodedDataOffset + maskedSeed.Length, maskedDB, 0, encodedDataCount - maskedSeed.Length);

            byte[] seedMask = mgf.GenerateMask(maskedDB, maskedSeed.Length);
            mSeed = new byte[maskedSeed.Length];
            for (int j = 0; j < maskedSeed.Length; j++)
            {
                mSeed[j] = (byte)(maskedSeed[j] ^ seedMask[j]);
            }
            //System.Diagnostics.Debug.WriteLine("Seed was " + ByteArrayToString(seed));
            byte[] dbMask = mgf.GenerateMask(mSeed, maskedDB.Length);
            byte[] data = maskedDB;
            for (int i = 0; i < maskedDB.Length; i++)
            {
                data[i] ^= dbMask[i];
            }
            //System.Diagnostics.Debug.WriteLine("Data was " + ByteArrayToString(data));
            return data;
        }

        //static string ByteArrayToString(byte[] ba)
        //{
        //    string hex = BitConverter.ToString(ba);
        //    return hex.Replace("-", "");
        //}

    }
}
