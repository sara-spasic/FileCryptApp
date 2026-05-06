using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal interface IEncryptionAlgorithm
    {
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);

        string Name { get; }
    }
}
