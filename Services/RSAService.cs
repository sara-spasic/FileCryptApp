using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal class RSAService
    {
         
        private  RSA rsa;

        public RSAService()
        {
            rsa = RSA.Create(2048);

        }

        public byte[] Encrypt(byte[] data,RSAParameters parameters)
        {
            //zbog testiranja na jednom racunaru moram ovde da ga kreiram kao privremeni 
            using RSA r= RSA.Create();
            r.ImportParameters(parameters);
            //rsa.ImportParameters(parameters);
            return r.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

        }

        public byte[] Decrypt(byte[] data, RSAParameters parameters) { 
            
            using RSA r = RSA.Create();
            r.ImportParameters(parameters);
            return r.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
        }

        public RSAParameters GetPublicKey() {

            return rsa.ExportParameters(false);
        }

        public RSAParameters GetPrivateKey()
        {
            return rsa.ExportParameters(true);
        }
    }
}
