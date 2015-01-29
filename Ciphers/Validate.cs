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
                throw new ArgumentException("The data offset parameter was < 0", "inputOffset");
            }
            if (inputCount <= 0)
            {
                // TODO
                throw new ArgumentException("The data length parameter was < 0", "inputCount");
            }

            if (inputBuffer.Length < inputCount)
            {
                throw new ArgumentException("The specified number of bytes to use was larger than the length of the data provided", "inputCount");
            }

            if (inputBuffer.Length < inputOffset)
            {
                throw new ArgumentException("The specified data offset was beyond the length of the data provided", "inputOffset");
            }

            // No need to check for reading beyond end of array and .Net will throw if this happens
            if (inputBuffer.Length < inputOffset + inputCount)
            {
                throw new ArgumentException("The data range specified by the offset and number of bytes to use was more than is available by the data");
            }

            // Account for values of inputOffset and inputCount that might overflow.
            if ((inputOffset + inputCount < inputCount) ||
                (inputOffset + inputCount < inputOffset))
            {
                System.Diagnostics.Debug.WriteLine("hit condition");
                throw new ArgumentException("The data offset or length parameter is too large");
            }
        }
    }
}
