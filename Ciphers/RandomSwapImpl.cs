using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
    public class RandomSwapImpl : IRandomSwap
    {
        System.Security.Cryptography.RandomNumberGenerator moRng;

        public RandomSwapImpl() : this(new System.Security.Cryptography.RNGCryptoServiceProvider())
        {
        }

        public RandomSwapImpl(System.Security.Cryptography.RandomNumberGenerator rng)
        {
            moRng = rng;
        }

        public byte[] Swap(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            #region Validate
            Validate.AnArray(inputBuffer, inputOffset, inputCount);
            if (inputCount % 2 != 0)
            {
                // Our data needs to be split in half so it needs to be even in length
                throw new ArgumentException("inputCount needs to be even", "inputCount");
            }
            #endregion

            byte[] random = new byte[1];
            // We only need 1 bit of randomness, but we generate randomness by the byte
            moRng.GetBytes(random);

            byte[] ret = new byte[inputCount];
            // Since the random bit is a secret, we want the same operations to occur regardless of value, implying constant time operations, to help
            // avoid any side channel info leaks due to timing.
            if ((random[0] & (byte)0x01) == (byte)0x01)
            {
                // Swap
                Buffer.BlockCopy(inputBuffer, inputOffset, ret, inputCount / 2, inputCount / 2);
                Buffer.BlockCopy(inputBuffer, inputOffset + inputCount / 2, ret, 0, inputCount / 2);
            }
            else
            {
                // Don't swap
                Buffer.BlockCopy(inputBuffer, inputOffset, ret, 0, inputCount / 2);
                Buffer.BlockCopy(inputBuffer, inputOffset + inputCount / 2, ret, inputCount / 2, inputCount / 2);
            }

            // Zero out random[0] as it contains sensitive data
            random[0] = 0;

            return ret;
        }
    }
}
