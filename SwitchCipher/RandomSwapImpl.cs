using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SwitchCipher
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

        public byte[] Swap(byte[] src, int srcOffset, int count)
        {
            if (count == 0)
            {
                // dataPair needs to be > 0 in length
                // TODO throw
                throw new Exception("count needs to be greater than 0");
            }
            if (count % 2 != 0)
            {
                // dataPair needs to be even in length
                // TODO throw
                throw new Exception("count needs to be even");
            }

            byte[] random = new byte[1];
            // We only need 1 bit of randomness, but we generate randomness by the byte
            moRng.GetBytes(random);

            byte[] ret = new byte[count];
            // Since the random bit is a secret, we want the same operations to occur regardless of value, implying constant time operations, to help
            // avoid any side channel info leaks due to timing.
            if ((random[0] & (byte)0x01) == (byte)0x01)
            {
                // Swap
                Buffer.BlockCopy(src, srcOffset, ret, count / 2, count / 2);
                Buffer.BlockCopy(src, srcOffset + count / 2, ret, 0, count / 2);
            }
            else
            {
                // Don't swap
                Buffer.BlockCopy(src, srcOffset, ret, 0, count / 2);
                Buffer.BlockCopy(src, srcOffset + count / 2, ret, count / 2, count / 2);
            }

            // Zero out random[0] as it contains sensitive data
            random[0] = 0;

            return ret;
        }
    }
}
