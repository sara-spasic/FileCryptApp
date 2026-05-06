using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal class XXTEA:IEncryptionAlgorithm
    {
        private readonly byte[] key;
        private const uint DELTA = 0x9e3779b9;

        public XXTEA(byte[] key){
            

            this.key = new byte[16];

            if (key != null)
            {
              
                int len = Math.Min(key.Length, 16);
                Array.Copy(key, 0, this.key, 0, len);
            }


        }

        public string Name => "XXTEA";
        public byte[] Encrypt(byte[] data)
        {
            if (data == null || data.Length == 0)
                return Array.Empty<byte>();

           

            uint[] dataUints = BytesToUints(data);
            uint[] keyUints= BytesToUints(this.key);

            EncryptionCore(dataUints, keyUints);

            return UintsToBytes(dataUints);

        }
        public byte[] Decrypt(byte[] data)
        {
            if (data == null || data.Length == 0)
                return Array.Empty<byte>();

            if (data.Length % 4 != 0)
                throw new Exception("Podatak mora biti deljiv sa 4!");

            uint[] dataUints= BytesToUints(data);
            uint[] keyUints=BytesToUints(this.key);

            DecryptCore(dataUints, keyUints);
            
            byte[] result= UintsToBytes(dataUints);

            return result;
        }

        private static uint MX(uint sum, uint y, uint z, int p, uint e, uint[] k)
        {
            return ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
        }


        private void EncryptionCore(uint[] v, uint[] k)
        {
            int n = v.Length;
            if (n <= 1) return;

            uint z = v[n - 1];
            uint sum = 0;
            int q = 6 + 52 / n;

            for (int i = 0; i < q; i++)
            {
                sum += DELTA;
                uint e = (sum >> 2) & 3;

                for (int p = 0; p < n - 1; p++)
                {
                    uint y = v[p + 1];
                    v[p] += MX(sum, y, z, p, e, k);
                    z = v[p];
                }

                uint yFirst = v[0];
                v[n - 1] += MX(sum, yFirst, z, n - 1, e, k);
                z = v[n - 1];
            }
        }

        private void DecryptCore(uint[] v, uint[] k)
        {
            int n = v.Length;
            if(n<= 1) return;

            uint y = v[0];
            int q = 6 + 52 / n;
            uint sum = (uint)(q * DELTA);

            while (sum != 0)
            {
                uint e=(sum >> 2) & 3;
                for (int p = n - 1; p > 0; p--) {
                    uint z = v[p - 1];
                    v[p] -= MX(sum, y, z, p, e, k);
                    y = v[p];
                }

                uint zFirst = v[n - 1];
                v[0] -= MX(sum, y, zFirst, 0, e, k);
                y = v[0];

                sum -= DELTA;

            }
        }

        private static uint[] BytesToUints(byte[] v)
        {
            int count = (v.Length+3) / 4;
            uint[] result=new uint[count];
            Buffer.BlockCopy(v, 0, result, 0, v.Length);
            return result;
        }

        private static byte[] UintsToBytes(uint[] v)
        {
            byte[] result=new byte[v.Length * 4];
            Buffer.BlockCopy(v,0,result,0,result.Length);
            return result;
        }

        private static byte[] AddPadding(byte[] v)
        {
            int padding = 4-(v.Length % 4);
            if (padding == 4) padding = 0;

            byte[] padded = new byte[v.Length + padding];

            Array.Copy(v, padded, v.Length);

            for (int i = v.Length; i < padded.Length; i++)
                padded[i] = (byte)padding;

            return padded;
        }

        private static byte[] RemovePadding(byte[] v)
        {
            if (v.Length == 0) return v;

            int padding = v[v.Length - 1];
            if(padding>4 || padding<=0) return v;

            for (int i = v.Length - padding; i < v.Length; i++)
                if (v[i] != padding) return v;

            byte[] result = new byte[v.Length - padding];

            Array.Copy(v, result, result.Length);

            return result;
        }

        public static byte[] GenerateKey()
        {
            byte[] key = new byte[16];
            using(var randomNumber = RandomNumberGenerator.Create())
            {
                randomNumber.GetBytes(key);
            }
            Console.WriteLine(key);
            return key;
        }

    }


}
