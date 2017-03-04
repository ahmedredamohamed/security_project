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
            throw new NotImplementedException();
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
