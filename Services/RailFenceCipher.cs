using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal class RailFenceCipher : IEncryptionAlgorithm
    {
        private readonly int railsKey;
        

        public RailFenceCipher(int rails=3)
        {
            this.railsKey = rails;
            
        }

        public string Name => "RailFenceCipher";
        public byte[] Encrypt(byte[] data){
            if(data == null||data.Length==0)
                return Array.Empty<byte>();
            int[] pattern = GetRailPattern(data.Length, this.railsKey);
            byte[] result = new byte[data.Length];
            int k = 0;

            for (int j=0;j<this.railsKey;j++)
            {
                for(int i = 0; i < data.Length; i++)
                {
                    if(pattern[i] == j)
                    {
                        result[k++] = data[i];
                    }
                }
            }
            return result;
        }
        public byte[] Decrypt(byte[] data) {
            if (data == null || data.Length == 0)
                return Array.Empty<byte>();

            int[] pattern = GetRailPattern(data.Length, this.railsKey);
            byte[] result= new byte[data.Length];
            int k = 0;

            byte[,] railMatrix = new byte[railsKey, data.Length];

            for (int j = 0; j < railsKey; j++)
            {
                for (int i = 0; i < data.Length; i++)
                {
                    if (pattern[i] == j)
                    {
                        railMatrix[j,i]= data[k++];
                    }
                }
            }

            for (int i=0; i<data.Length; i++)
            {
                result[i] = railMatrix[pattern[i],i];
            }

            return result;
        }

        private int[] GetRailPattern(int datalength,int railsKey)
        {
            int[] pattern= new int[datalength];
            int row = 0;
            bool dirDown= false;

            for(int i = 0; i < datalength; i++) 
            {
                pattern[i] = row;
                if (row == 0 || row == railsKey - 1) 
                    dirDown = !dirDown;
                if (dirDown)
                    row++;
                else
                    row--;
                }
            return pattern;
        }
        private static char[,] RailMatrix(string text,int railsKey)
        {
            char[,] rail = new char[railsKey, text.Length];
            for (int i = 0; i < railsKey; i++)
                for (int j = 0; j < text.Length; j++)
                    rail[i, j] = '\n';
            return rail;           
        }

        private static string EncryptText(string text,int railsKey)
        {
            bool dirDown = false;
            int row = 0,col = 0;

            char[,] rail= RailMatrix(text, railsKey);

            for (int i = 0; i < text.Length; i++) { 
                
                if(row==0||row==railsKey-1)
                    dirDown = !dirDown;

                rail[row,col++]= text[i];

                if(dirDown)
                    row++;
                else
                    row--;

            }

            string result = "";
            for (int i = 0;i < railsKey; i++)
                for(int j = 0;j < text.Length; j++)
                    if (rail[i,j]!='\n')
                        result += rail[i,j];

            return result;

        }

        private static string DecryptText(string cipher, int railsKey)
        {
            bool dirDown = true;
            int row = 0, col = 0;

            char[,] rail = RailMatrix(cipher, railsKey);

            for (int i = 0; i < cipher.Length; i++){

                if (row == 0)
                    dirDown = true;
                if (row == railsKey - 1)
                    dirDown = false;

                rail[row, col++] = '*';

                if(dirDown)
                    row++;
                else
                    row--;

            }

            int index = 0;
            for (int i = 0; i < railsKey; i++)
                for (int j = 0; j < cipher.Length; j++)
                    if(rail[i,j]=='*'&& index<cipher.Length)
                        rail[i,j] = cipher[index++];

            string result = "";
            row = 0;
            col = 0;

            for(int i = 0; i<cipher.Length;i++){
                if (row == 0)
                    dirDown = true;
                if (row == railsKey - 1)
                    dirDown = false;

                if (rail[row,col]!='*')
                    result += rail[row,col++];

                if (dirDown)
                    row++;
                else
                    row--;

            }

            return result;

        }


    }
}
