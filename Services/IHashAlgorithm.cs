using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal interface IHashAlgorithm
    {
        byte[] Hash(byte[] data);

        string Name { get; }

       
        int HashSize { get; }

    }
}
