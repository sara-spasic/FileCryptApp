using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal class TigerHash : IHashAlgorithm    {
        private ulong H0 = 0x0123456789ABCDEFUL;
        private ulong H1 = 0xFEDCBA9876543210UL;
        private ulong H2 = 0xF096A5B4C3B2E187UL;

        private static readonly ulong[] S1 = TigerSBoxes.S1;
        private static readonly ulong[] S2 = TigerSBoxes.S2;
        private static readonly ulong[] S3 = TigerSBoxes.S3;
        private static readonly ulong[] S4 = TigerSBoxes.S4;

        public int HashSize => 24;
        public string Name => "Tiger-Hash";
        public byte[] Hash(byte[] data)
        {
            byte[] padded = AddPadding(data);

            for (int offset = 0; offset < padded.Length; offset += 64)
            {
                ulong[] W = new ulong[8];

                
                for (int i = 0; i < 8; i++)
                {
                    ulong val = BitConverter.ToUInt64(padded, offset + i * 8);
                    W[i] = val;
                }

                ProcessBlock(W);
            }

            byte[] result = new byte[24];
            Array.Copy(BitConverter.GetBytes(H0), 0, result, 0, 8);
            Array.Copy(BitConverter.GetBytes(H1), 0, result, 8, 8);
            Array.Copy(BitConverter.GetBytes(H2), 0, result, 16, 8);

            return result;
        }

        private byte[] AddPadding(byte[] message)
        {
            int baseLen = message.Length;
            int m = baseLen % 64;
            int paddingLength = (64 - m);
            if (paddingLength < 9)
                paddingLength += 64;

            byte[] padded = new byte[baseLen + paddingLength];
            Array.Copy(message, padded, baseLen);

            padded[baseLen] = 0x01;

            ulong bitLength = (ulong)baseLen * 8;
            Array.Copy(BitConverter.GetBytes(bitLength), 0, padded, padded.Length - 8, 8);

            return padded;
        }

        private void ProcessBlock(ulong[] W)
        {
            ulong a = H0;
            ulong b = H1;
            ulong c = H2;

            for (int pass = 0; pass < 3; pass++)
            {
                KeySchedule(W, pass);

                for (int j = 0; j < 8; j++)
                {
                    c ^= W[j];

                    byte c0 = (byte)(c & 0xff);
                    byte c1 = (byte)((c >> 8) & 0xff);
                    byte c2 = (byte)((c >> 16) & 0xff);
                    byte c3 = (byte)((c >> 24) & 0xff);
                    byte c4 = (byte)((c >> 32) & 0xff);
                    byte c5 = (byte)((c >> 40) & 0xff);
                    byte c6 = (byte)((c >> 48) & 0xff);
                    byte c7 = (byte)((c >> 56) & 0xff);

                    a -= (S1[c0] ^ S2[c2] ^ S3[c4] ^ S4[c6]);
                    b += (S4[c1] ^ S3[c3] ^ S2[c5] ^ S1[c7]);
                    b *= (ulong)(pass + 1);
                }
            }

            H0 += a;
            H1 += b;
            H2 += c;
        }

        private void KeySchedule(ulong[] W, int pass)
        {
            if (pass == 0)
            {
                W[0] = W[0] - (W[7] ^ 0xA5A5A5A5A5A5A5A5UL);
                W[1] ^= W[0];
                W[2] += W[1];
                W[3] = W[3] - (W[2] ^ ((W[1] ^ 0xFFFFFFFFFFFFFFFFUL) << 19));
                W[4] ^= W[3];
                W[5] += W[4];
                W[6] = W[6] - (W[5] ^ ((W[4] ^ 0xFFFFFFFFFFFFFFFFUL) >> 23));
                W[7] ^= W[6];
            }
            else if (pass == 1)
            {
                W[0] += W[7];
                W[1] = W[1] - (W[0] ^ ((W[0] ^ 0xFFFFFFFFFFFFFFFFUL) << 19));
                W[2] ^= W[1];
                W[3] += W[2];
                W[4] = W[4] - (W[3] ^ ((W[2] ^ 0xFFFFFFFFFFFFFFFFUL) >> 23));
                W[5] ^= W[4];
                W[6] += W[5];
                W[7] = W[7] - (W[6] ^ 0x0123456789ABCDEFUL);
            }
            else
            {
                W[0] = W[0] - (W[7] ^ 0xA5A5A5A5A5A5A5A5UL);
                W[1] ^= W[0];
                W[2] += W[1];
                W[3] = W[3] - (W[2] ^ ((W[1] ^ 0xFFFFFFFFFFFFFFFFUL) << 19));
                W[4] ^= W[3];
                W[5] += W[4];
                W[6] = W[6] - (W[5] ^ ((W[4] ^ 0xFFFFFFFFFFFFFFFFUL) >> 23));
                W[7] ^= W[6];
            }
        }
    }

}

