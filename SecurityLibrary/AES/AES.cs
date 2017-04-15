using MathNet.Numerics.LinearAlgebra;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        byte[,] Sbox = new byte[16, 16] {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

        byte[,] inverseSbox = new byte[16, 16]{
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

        byte[,] mixColumnMatrix = new byte[4, 4] {
            { 0x02, 0x03, 0x01, 0x01 },
            { 0x01, 0x02, 0x03, 0x01 },
            { 0x01, 0x01, 0x02, 0x03 },
            { 0x03, 0x01, 0x01, 0x02 }};

        byte[,] Rcon=new byte[10, 4] {
            {0x01, 0x00, 0x00, 0x00},
            {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00},
            {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00},
            {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00},
            {0x80, 0x00, 0x00, 0x00},
            {0x1b, 0x00, 0x00, 0x00},
            {0x36, 0x00, 0x00, 0x00} };

        byte[,] Key;

        public override string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            KeySchedule(key);
            byte[] cipherTextByteArr;
            if (cipherText[0].Equals('0') && cipherText[1].Equals('x'))
            {
                byte[] temp = new byte[(cipherText.Length - 2) / 2];
                int t = 0;
                for (int i = 0; i < temp.Length; i++)
                {
                    temp[i] = Convert.ToByte(cipherText.Substring(t + 2, 2), 16);
                    t += 2;
                }
                int tempLength = temp.Length;
                while (tempLength % 16 != 0)
                    tempLength++;
                cipherTextByteArr = new byte[tempLength];
                Array.Copy(temp, cipherTextByteArr, temp.Length);
                tempLength = temp.Length;
                for (; tempLength < cipherTextByteArr.Length; tempLength++)
                    cipherTextByteArr[tempLength] = Convert.ToByte("00", 16);
                plainText += "0x";
            }
            else
                cipherTextByteArr = new byte[plainText.Length];
            int cipherTextIndex = 0;
            while (true)
            {
                if (cipherTextIndex == cipherTextByteArr.Length)
                    break;
                byte[,] state = new byte[4, 4];
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                    {
                        state[j, i] = cipherTextByteArr[cipherTextIndex];
                        cipherTextIndex++;
                    }
                byte[,] currentKey = new byte[4, 4];
                int keyRow = 0;
                int keyCol = 0;
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        currentKey[j, i] = this.Key[keyRow, keyCol];
                        keyCol++;
                    }
                    keyRow++;
                    keyCol = 0;
                }
                state = addRoundKey(state, currentKey);
                for (int i = 0; i < 9; i++)
                {
                    state = invShiftRows(state);
                    state = invSubBytes(state);
                    state = invMixColumns(state);

                    for (int q = 0; q < 4; q++)
                    {
                        for (int m = 0; m < 4; m++)
                        {
                            currentKey[m, q] = this.Key[keyRow, keyCol];
                            keyCol++;
                        }
                        keyRow++;
                        keyCol = 0;
                    }
                    state = addRoundKey(state, currentKey);
                }
                state = invShiftRows(state);
                state = invSubBytes(state);

                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        currentKey[j, i] = this.Key[keyRow, keyCol];
                        keyCol++;
                    }
                    keyRow++;
                    keyCol = 0;
                }
                state = addRoundKey(state, currentKey);
                byte[] temp = new byte[16];
                int s = 0;
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                    {
                        temp[s] = state[j, i];
                        s++;
                    }
                plainText += BitConverter.ToString(temp).Replace("-", string.Empty);
            }

            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            KeySchedule(key);
            byte[] plainTextByteArr;
            if (plainText[0].Equals('0') && plainText[1].Equals('x'))
            {
                byte[] temp = new byte[(plainText.Length-2) / 2];
                int t = 0;
                for (int i = 0; i < temp.Length; i++)
                {
                    temp[i] = Convert.ToByte(plainText.Substring(t + 2, 2), 16);
                    t += 2;
                }
                int tempLength = temp.Length;
                while (tempLength % 16 != 0)
                    tempLength++;
                plainTextByteArr = new byte[tempLength];
                Array.Copy(temp, plainTextByteArr, temp.Length);
                tempLength = temp.Length;
                for (; tempLength < plainTextByteArr.Length; tempLength++)
                    plainTextByteArr[tempLength] = Convert.ToByte("00", 16);
                cipherText += "0x";
            }
            else
                plainTextByteArr = new byte[plainText.Length];
            int plainTextIndex = 0;
            while (true)
            {
                if (plainTextIndex == plainTextByteArr.Length)
                    break;
                byte[,] state = new byte[4,4];
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                    {
                        state[j, i] = plainTextByteArr[plainTextIndex];
                        plainTextIndex++;
                    }

                //byte[,] state = convertStringToBytes(subPlainText);
                byte[,] currentKey = new byte[4, 4];
                int keyRow = 0;
                int keyCol = 0;
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        currentKey[j, i] = this.Key[keyRow, keyCol];
                        keyCol++;
                    }
                    keyRow++;
                    keyCol = 0;
                }
                state = addRoundKey(state, currentKey);
                for (int i = 0; i < 9; i++)
                {
                    state = subBytes(state);
                    state = shiftRows(state);
                    state = mixColumns(state);

                    for (int q = 0; q < 4; q++)
                    {
                        for (int m = 0; m < 4; m++)
                        {
                            currentKey[m, q] = this.Key[keyRow, keyCol];
                            keyCol++;
                        }
                        keyRow++;
                        keyCol = 0;
                    }
                    state = addRoundKey(state, currentKey);
                }
                state = subBytes(state);
                state = shiftRows(state);

                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        currentKey[j, i] = this.Key[keyRow, keyCol];
                        keyCol++;
                    }
                    keyRow++;
                    keyCol = 0;
                } 
                state = addRoundKey(state, currentKey);
                byte[] temp = new byte[16];
                int s = 0;
                for(int i=0; i<4; i++)
                    for(int j=0; j<4; j++)
                    {
                        temp[s] = state[j,i];
                        s++;
                    }
                cipherText += BitConverter.ToString(temp).Replace("-", string.Empty);
            }
            
            return cipherText;
        }

        private void KeySchedule (string key)
        {
            byte[] temp = new byte[16];
            int j = 0;
            
            for(int i=0;i<16;i++)
            {
                temp[i] = Convert.ToByte(key.Substring(j+ 2, 2), 16);
                j += 2;
            }
            j = 0;
            
            this.Key = new byte[44, 4];
            for (int i = 0; i < 4; i++)
                for (int k = 0; k < 4; k++)
                    this.Key[i,k] = temp[j++];

            for(int i=1;i<11;i++)
            {
                for (int l = 0; l < 4; l++)
                {
                    byte[] word = new byte[4];
                    if (l == 0)
                    {
                        byte tmp = this.Key[(4 * i) - 1 + l, 0];
                        word[0] = this.Key[(4 * i) - 1 + l, 1];
                        word[1] = this.Key[(4 * i) - 1 + l, 2];
                        word[2] = this.Key[(4 * i) - 1 + l, 3];
                        word[3] = tmp;
                        for (int k = 0; k < 4; k++)
                            word[k] = Sbox[word[k] >> 4, word[k] & 0x0f];
                    }
                    else
                    {
                        word[0] = this.Key[(4 * i) - 1 + l, 0];
                        word[1] = this.Key[(4 * i) - 1 + l, 1];
                        word[2] = this.Key[(4 * i) - 1 + l, 2];
                        word[3] = this.Key[(4 * i) - 1 + l, 3];
                    }
                    for (int k = 0; k < 4; k++)
                        if (l == 0)
                            word[k] = Convert.ToByte(this.Key[(4 * i) - 4+l, k ] ^ word[k] ^ Rcon[i-1, k ]);
                        else
                            word[k] = Convert.ToByte(this.Key[(4 * i) - 4+l, k] ^ word[k]);

                    this.Key[(4 * i)+l, 0] = word[0];
                    this.Key[(4 * i)+l, 1] = word[1];
                    this.Key[(4 * i)+l, 2] = word[2];
                    this.Key[(4 * i)+l, 3] = word[3];
                }
            }

        }   

        public byte[,] subBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = Sbox[state[i, j] >> 4, state[i, j] & 0x0f];
            return state;
        }

        static byte[,] shiftRows(byte[,] state)
        {
            byte temp;

            //Second Row:
            temp = state[1, 0];
            for (int i = 0; i < 3; i++)
                state[1, i] = state[1, i + 1];
            state[1, 3] = temp;

            //Third Row:
            temp = state[2, 0];
            for (int i = 0; i < 3; i++)
                state[2, i] = state[2, i + 1];
            state[2, 3] = temp;
            temp = state[2, 0];
            for (int i = 0; i < 3; i++)
                state[2, i] = state[2, i + 1];
            state[2, 3] = temp;

            //Forth Row:
            temp = state[3, 0];
            for (int i = 0; i < 3; i++)
                state[3, i] = state[3, i + 1];
            state[3, 3] = temp;
            temp = state[3, 0];
            for (int i = 0; i < 3; i++)
                state[3, i] = state[3, i + 1];
            state[3, 3] = temp;
            temp = state[3, 0];
            for (int i = 0; i < 3; i++)
                state[3, i] = state[3, i + 1];
            state[3, 3] = temp;

            return state;
        }

        private byte[,] addRoundKey(byte[,] state, byte[,] roundKey)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] ^= roundKey[i, j];
            return state;
        }

        private byte[,] mixColumns(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte[] vector = new byte[4];

                for (int j = 0; j < 4; j++)
                    vector[j] = state[j, i];

                //                  [0x02      |      0x03      |      0x01      |      0x01]
                state[0, i] = (byte)(GF2(vector[0]) ^ GF3(vector[1]) ^ vector[2] ^ vector[3]);

                //                  [0x01      |      0x02      |      0x03      |      0x01]
                state[1, i] = (byte)(vector[0] ^ GF2(vector[1]) ^ GF3(vector[2]) ^ (vector[3]));

                //                  [0x01      |      0x01      |      0x02      |      0x03]
                state[2, i] = (byte)((vector[0]) ^ (vector[1]) ^ GF2(vector[2]) ^ GF3(vector[3]));

                //                  [0x03      |      0x01      |      0x01      |      0x02]
                state[3, i] = (byte)(GF3(vector[0]) ^ (vector[1]) ^ (vector[2]) ^ GF2(vector[3]));
            }
            return state;
        }

        private byte GF2(byte input)
        {
            if (input < 0x80) //Input less than (1000 0000)2 so that shifting doesn't produce 1 in the MSB
            {
                input <<= 1;
                return input; //Multiply by 2 = Shift lift by 1
            }
            else
            {
                input <<= 1;
                return (byte)((input) ^ (0x1b)); //Mutiply by 2 then XOR with 1B
            }
        }

        private byte GF3(byte input)
        {
            byte inputGF = GF2(input);
            return (byte)(input ^ inputGF); //GF3(input) = XOR between original input and GF2(input)
        }

        private byte[,] invShiftRows(byte[,] state)
        {
            byte temp;

            //Second Row:
            temp = state[1, 3];
            for (int i = 3; i > 0; i--)
                state[1, i] = state[1, i - 1];
            state[1, 0] = temp;

            //Third Row:
            temp = state[2, 3];
            for (int i = 3; i > 0; i--)
                state[2, i] = state[2, i - 1];
            state[2, 0] = temp;
            temp = state[2, 3];
            for (int i = 3; i > 0; i--)
                state[2, i] = state[2, i - 1];
            state[2, 0] = temp;

            //Forth Row:
            temp = state[3, 3];
            for (int i = 3; i > 0; i--)
                state[3, i] = state[3, i - 1];
            state[3, 0] = temp;
            temp = state[3, 3];
            for (int i = 3; i > 0; i--)
                state[3, i] = state[3, i - 1];
            state[3, 0] = temp;
            temp = state[3, 3];
            for (int i = 3; i > 0; i--)
                state[3, i] = state[3, i - 1];
            state[3, 0] = temp;

            return state;
        }

        public byte[,] invSubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = inverseSbox[state[i, j] >> 4, state[i, j] & 0x0f];
            return state;
        }

        private byte[,] invMixColumns(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte[] vector = new byte[4];

                for (int j = 0; j < 4; j++)
                    vector[j] = state[j, i];

                //                  [0x0e      |      0x0b      |      0x0d      |      0x09]
                state[0, i] = (byte)(GFe(vector[0]) ^ GFb(vector[1]) ^ GFd(vector[2]) ^ GF9(vector[3]));

                //                  [0x09      |      0x0e      |      0x0b      |      0x0d]
                state[1, i] = (byte)(GF9(vector[0]) ^ GFe(vector[1]) ^ GFb(vector[2]) ^ GFd(vector[3]));

                //                  [0x0d      |      0x09      |      0x0e      |      0x0b]
                state[2, i] = (byte)(GFd(vector[0]) ^ GF9(vector[1]) ^ GFe(vector[2]) ^ GFb(vector[3]));

                //                  [0x0b      |      0x0d      |      0x09      |      0x0e]
                state[3, i] = (byte)(GFb(vector[0]) ^ GFd(vector[1]) ^ GF9(vector[2]) ^ GFe(vector[3]));
            }
            return state;
        }

        private byte GF9(byte input)
        {
            byte gf = GF2(input);
            gf = GF2(gf);
            gf = GF2(gf);
            return (byte)(gf ^ input); //X × 9 = (((X × 2) × 2) × 2)+X
        }

        private byte GFb(byte input)
        {
            byte gf = GF2(input);
            gf = GF2(gf);
            gf = GF2(gf);
            return (byte)(gf ^ GF2(input) ^ input); //X × 11 = ((((X × 2) × 2) + X) × 2) + X
        }

        private byte GFd(byte input)
        {
            byte gf = GF2(input);
            gf = GF2(gf);
            gf = GF2(gf);
            return (byte)(gf ^ GF2(GF2(input)) ^ input); //X × 13 = ((((X × 2) + X) × 2) × 2) + X
        }

        private byte GFe(byte input)
        {
            byte gf = GF2(input);
            gf = GF2(gf);
            gf = GF2(gf);
            return (byte)(gf ^ GF2(GF2(input)) ^ GF2(input)); //X × 14 = ((((X × 2) + X) × 2) + X) × 2
        }
    }
}
