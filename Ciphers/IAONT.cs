using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
    /*
     * Defines the interface for an All Or Nothing Transform (AONT) encoding 
    */
    public interface IAONT
    {
        byte[] Encode(byte[] message);

        byte[] Encode(byte[] message, int messageOffset, int messageCount);

        byte[] Decode(byte[] encodedMessage);

        byte[] Decode(byte[] encodedMessage, int encodedMessageOffset, int encodedMessageCount);

        byte[] Seed { get; set; }

        int seedSize { get;  set; }

        int outputLengthForInputLength(int inputLength);
    }
}
