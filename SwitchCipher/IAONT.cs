using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SwitchCipher
{
    /*
     * Defines the interface for an All Or Nothing Transform (AONT) encoding 
    */
    public interface IAONT
    {
        byte[] Encode(byte[] message);

        byte[] Decode(byte[] encodedMessage);

        int seedSize { get;  set; }

        int outputLengthForInputLength(int inputLength);
    }
}
