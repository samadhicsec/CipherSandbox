using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SwitchCipher
{
    public interface IRandomSwap
    {
        /*
         * Swap should randomly swap the 2 halves of the byte array passed in.  The byte array needs to be even in length.
         * Inputs:  src - a byte array containing the data
         *          srcOffset - the location within the src to start
         *          count - an even number of bytes to use
         * Output: The byte array with halves swapped, or not, as decided by an internally generated random bit.
         */
        byte[] Swap(byte[] src, int srcOffset, int count);
    }
}
