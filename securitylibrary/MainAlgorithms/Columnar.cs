using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int row_num = 2;
            string cipher = cipherText.ToLower();
            double length = plainText.Length;
            double cipherlength = cipher.Length;
            List<int> Key = new List<int>();
            for (int k = 0; k <= plainText.Length; k++)
            {
                double rowdouble = length / row_num;
                int col_num = (int)Math.Ceiling(rowdouble);
                char[,] tablePlain = new char[row_num, col_num];
                char[,] tableCipher = new char[row_num, col_num];
                int counterPlain = 0;
                int counterCipher = 0;
                string[] Textplain = new string[col_num];
                string[] CipherText = new string[col_num];
                for (int i = 0; i < row_num; i++)
                {
                    for (int j = 0; j < col_num; j++)
                    {
                        if (counterPlain >= length)
                        {
                            tablePlain[i, j] = 'x';
                        }
                        else
                        {
                            tablePlain[i, j] = plainText[counterPlain];
                            counterPlain++;
                        }
                    }
                }
                for (int j = 0; j < col_num; j++)
                {
                    for (int i = 0; i < row_num; i++)
                    {
                        if (counterCipher >= cipherlength)
                        {
                            tableCipher[i, j] = 'x';
                        }
                        else
                        {
                            tableCipher[i, j] = cipher[counterCipher];
                            counterCipher++;
                        }
                    }
                }
                    for (int i = 0; i < col_num; i++)
                    {
                        for (int j = 0; j < row_num; j++)
                        {
                            CipherText[i] += tableCipher[j, i];
                            Textplain[i] += tablePlain[j, i];
                        }
                }
                int counterMatching = 0;
                for (int i = 0; i < CipherText.Length; i++) {
                    for (int j = 0; j < Textplain.Length; j++) {
                        if (CipherText[i] == Textplain[j])
                        {
                            counterMatching++;
                        }
                    }
                }
                if (counterMatching == col_num)
                {
                    for(int i = 0; i< Textplain.Length; i++)
                    {
                        for (int j = 0; j < CipherText.Length; j++) {
                            if (Textplain[i] == CipherText[j]) {
                                Key.Insert(i, j + 1);
                                j = CipherText.Length;
                            }
                        }
                    }
                    break;
                }
                else {
                    row_num++; 
                }
            }
            if (Key.Count == 0) {
                for (int i = 0; i < 100; i++) {
                    Key.Add(0);
                }
            }
            return Key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int bigColNum = key.Max();
            double length = cipherText.Length;
            double rowdouble = length / bigColNum;
            int row_num = (int)Math.Ceiling(rowdouble);
            string plainText = "";
            int counter = 0;
            char[,] table = new char[row_num, bigColNum];
            char[,] DecrubtedTable = new char[row_num, bigColNum];
            for (int j = 0; j < bigColNum; j++)
            {
                for (int i = 0; i < row_num; i++)
                {
                    if (counter >= length)
                    {
                        break;
                    }
                    else
                    {
                        table[i, j] = cipherText[counter];
                        counter++;
                    }
                }
            }
 
           
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < row_num; j++)
                {
                    DecrubtedTable[j, i] = table[j, key.ElementAt(i) - 1];
                }
            }
            for (int i = 0; i < row_num; i++)
            {
                for (int j = 0; j < bigColNum; j++)
                {
                    if (DecrubtedTable[i, j] == 'x')
                    {
                        continue;
                    }
                    else
                    {
                        plainText += DecrubtedTable[i, j];
                    }
                }
            }
            return plainText.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int bigColNum = key.Max();
            double length = plainText.Length;
            double rowdouble = length / bigColNum;
            int row_num = (int)Math.Ceiling(rowdouble);
            string cipherText = "";
            int counter = 0;
            char[,] table = new char[row_num, bigColNum];
            Dictionary<int, int> dictionary = new Dictionary<int,int>();
            for (int i = 0; i < row_num; i++)
            {
                for (int j = 0; j < bigColNum; j++)
                {
                    if (counter >= length)
                    {
                        table[i, j] = 'x';
                    }
                    else
                    {
                        table[i, j] = plainText[counter];
                        counter++;
                    }
                }
            }
            for (int i = 0; i < key.Count; i++) {
                dictionary.Add(key.ElementAt(i),i);
            }
            for (int i = 0; i < key.Count; i++) {
                int index;
                dictionary.TryGetValue(i + 1, out index);
                for (int j = 0; j < row_num; j++) {
                    cipherText += table[j, index];
                }
            }
            return cipherText.ToUpper();
        }
    }
}
