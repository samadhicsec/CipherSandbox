using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
    public class Validate
    {
        public static void AnArray(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            // Make sure offset and count are positive
            if (inputOffset < 0)
            {
                // TODO
                throw new Exception("The data offset parameter was < 0");
            }
            if (inputCount <= 0)
            {
                // TODO
                throw new Exception("The data length parameter was < 0");
            }

            // No need to check for reading beyond end of array and .Net will throw if this happens

            // Account for values of inputOffset and inputCount that might overflow.
            if ((inputOffset + inputCount < inputCount) ||
                (inputOffset + inputCount < inputOffset))
            {
                // TODO
                throw new IndexOutOfRangeException("The data offset or length parameters is too large");
            }
        }
    }
}
