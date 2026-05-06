using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal class KeyManager
    {
        private readonly RSAService rsaService;

        public KeyManager(RSAService rsaService)
        {
            this.rsaService = rsaService;
        }
        public  byte[] GenerateXXTEAKey()
        {
            return XXTEA.GenerateKey();
        }

        

        public  void SaveKey(string path, byte[] key)
        {
            File.WriteAllBytes(path, key);
        }


        public  byte[] LoadKey(string path) { 
            return File.ReadAllBytes(path);
        }

        public  byte[] EncryptKeyRSA(byte[] symmetricKey,RSAParameters publicKey)
        {
            return rsaService.Encrypt(symmetricKey, publicKey);
        }

        public byte[] DecryptKeyRSA(byte[] encryptedKey,RSAParameters privateKey)
        {
            return rsaService.Decrypt(encryptedKey, privateKey);
        }
    }


}
