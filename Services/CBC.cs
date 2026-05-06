using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace FileCryptApp.Services
{
    internal class CBC: IEncryptionAlgorithm
    { 
        private readonly IEncryptionAlgorithm algorithm;

        private readonly byte[] iv;
        private readonly int blockSize=16;
        public CBC(IEncryptionAlgorithm algorithm, byte[] iv=null)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            
            this.algorithm = algorithm;
            if (iv == null)
            {
                this.iv = GenerateRandomIV(blockSize);
            }
            else
            {
                if (iv.Length < blockSize)
                    throw new Exception($"IV mora biti {blockSize} bajtova ");
                this.iv = iv;
            }

        }

        public string Name => $"CBC({algorithm.Name})";

        public byte[] Encrypt(byte[] data)
        {
            if(data==null||data.Length==0)
                return Array.Empty<byte>();

            byte[] paddedData= AddPadding(data);

            List<byte[]> blocks= SplitIntoBlocks(paddedData,blockSize);

            List<byte[]> encryptedBlocks=EncryptBlocks(blocks);

            byte[] encryptedData = FlattenBlocks(encryptedBlocks);

            byte[] result = new byte[iv.Length+encryptedData.Length];
            Array.Copy(iv,0,result,0,iv.Length);
            Array.Copy(encryptedData, 0, result, iv.Length, encryptedData.Length);

            return result;

        }

        public byte[] Decrypt(byte[] data)
        {
            if (data == null || data.Length == 0)
                return Array.Empty<byte>();

            if (data.Length < blockSize)
                throw new Exception("Sifrovani podaci su prekratki");

            byte[] iv=new byte[blockSize];
            Array.Copy(data,0,iv,0,blockSize);

            int encryptedBlocksLength= data.Length-blockSize;

            if (encryptedBlocksLength % blockSize != 0)
                throw new Exception("Sifrovani podaci nisu povezani po bloku");

            byte[] blocksData=new byte[encryptedBlocksLength];

            Array.Copy(data,blockSize,blocksData,0,encryptedBlocksLength);

            List<byte[]> blocks = SplitIntoBlocks(blocksData,blockSize);

            List<byte[]> decryptedBlocks = DecryptBlocks(blocks,iv);

            byte[] decryptedData= FlattenBlocks(decryptedBlocks);
            return RemovePadding(decryptedData);
        }

        public byte[] FlattenBlocks(List<byte[]> blocks)
        {
            int totalLength = blocks.Sum(block => block.Length);
            byte[] result=new byte[totalLength];

            int offset = 0;
            foreach (byte[] block in blocks)
            {
                Array.Copy(block, 0, result, offset, block.Length);
                offset += block.Length;
            }
            return result;
        }

        private byte[] GenerateRandomIV(int size)
        {
            byte[] iv = new byte[size];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { 
                rng.GetBytes(iv);
            }
            return iv;
        }
        public byte[] GetIV() => iv;

        private  byte[] AddPadding(byte[] data)
        {
            int paddingLength = blockSize - (data.Length % blockSize);
            if (paddingLength == 0) paddingLength = blockSize;

            byte[] padded = new byte[data.Length + paddingLength];

            Array.Copy(data, padded, data.Length);

            for (int i = data.Length; i < padded.Length; i++)
                padded[i] = (byte)paddingLength;

            return padded;
        }

        private  byte[] RemovePadding(byte[] data)
        {
            if (data.Length == 0) return data;

            int paddingLength = data[data.Length - 1];
            if (paddingLength <= 0 || paddingLength > blockSize || paddingLength > data.Length)
                throw new Exception("Neispravan padding");

            for (int i = data.Length - paddingLength; i < data.Length; i++)
            {
                if (data[i] != paddingLength)
                    throw new Exception("Neispravan padding");
                 
            }

            byte[] result = new byte[data.Length - paddingLength];

            Array.Copy(data,0, result,0, result.Length);

            return result;
        }

        private List<byte[]> SplitIntoBlocks(byte[] data,int size)
        {
            List<byte[]> blocks= new List<byte[]>();

            for(int i=0; i < data.Length; i+=size)
            {
                byte[] block= new byte[size];
                Array.Copy(data,i,block,0, Math.Min(size, data.Length - i));
                blocks.Add(block);
            }
            return blocks;
        }

        private byte[] XorBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) throw new Exception("Nizovi moraju biti iste duzine");
            byte[] result = new byte[a.Length];

            for(int i=0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }

        private List<byte[]> EncryptBlocks(List<byte[]> blocks)
        {
            List<byte[]> encryptedBlocks = new List<byte[]>();
            byte[] prevBlock = iv;

            foreach (byte[] block in blocks)
            {
                byte[] xored= XorBytes(block, prevBlock);

                byte[] encryptedBlock= algorithm.Encrypt(xored);
                encryptedBlocks.Add(encryptedBlock);
                prevBlock = encryptedBlock;
            }
            return encryptedBlocks;
        }

        private List<byte[]> DecryptBlocks(List<byte[]> blocks,byte[] ivFromFile) {

            List<byte[]> decryptedBlocks = new List<byte[]>();
            byte[] prevBlock = ivFromFile;

            foreach (byte[] block in blocks)
            {
                byte[] decryptedBlock = algorithm.Decrypt(block);
                byte[] xored = XorBytes(decryptedBlock, prevBlock);

                decryptedBlocks.Add(xored);
                prevBlock = block;
            }
            return decryptedBlocks;
        }


    }
}
