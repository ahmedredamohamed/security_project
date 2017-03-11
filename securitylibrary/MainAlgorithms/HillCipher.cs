using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int[,] keyMatrix;
            int[,] plainMatrix;
            int[,] cipherMatrix;
            int matrixSize;
            if (key.Count % 2 == 0)
                matrixSize = 2;
            else
                matrixSize = 3;
            keyMatrix = new int[matrixSize, matrixSize];
            plainMatrix = new int[matrixSize, plainText.Count / matrixSize];
            cipherMatrix = new int[matrixSize, plainText.Count / matrixSize];
            List<int> cipherList = new List<int>();
            addKeyListInMatrix(key, ref keyMatrix, matrixSize);
            addPlainListInMatrix(plainText, ref plainMatrix, matrixSize, plainText.Count / matrixSize);
            matrixMultiplication(keyMatrix, plainMatrix, plainText.Count / matrixSize, matrixSize, ref cipherMatrix);
            addCipherMatrixToList(ref cipherList, cipherMatrix, matrixSize, plainText.Count / matrixSize);
            return cipherList;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            List<int> plainTextList = new List<int>();
            List<int> keyList = new List<int>();
            List<int> cipherList = new List<int>();
            string cipherString = "";
            getCharactersNumbers(ref plainTextList, plainText);
            getCharactersNumbers(ref keyList, key);
            cipherList = Encrypt(plainTextList, keyList);
            getNumbersCharacters(ref cipherString, cipherList);
            return cipherString;
            //throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }

        private void addKeyListInMatrix(List<int> keyList, ref int[,] keyMatrix, int matrixSize)
        {
            int keyListIndex = 0;
            for (int i = 0; i < matrixSize; i++)
            {
                for (int j = 0; j < matrixSize; j++)
                {
                    keyMatrix[i, j] = keyList[keyListIndex];
                    keyListIndex++;
                }
            }
        }

        private void addPlainListInMatrix(List<int> plainList, ref int[,] plainVector, int numOfRows, int numOfCoulmns)
        {
            int plainTextListIndex = 0;
            for (int i = 0; i < numOfCoulmns; i++)
            {
                for (int j = 0; j < numOfRows; j++)
                {
                    plainVector[j, i] = plainList[plainTextListIndex];
                    plainTextListIndex++;
                }
            }
        }

        private void addCipherMatrixToList(ref List<int> cipherlist, int[,] ciphermatrix, int numOfRows, int numOfCoulmns)
        {
            for (int i = 0; i < numOfCoulmns; i++)
            {
                for (int j = 0; j < numOfRows; j++)
                {
                    cipherlist.Add(ciphermatrix[j, i]);
                }

            }
        }

        private void matrixMultiplication(int[,] firstMatrix, int[,] secondMatrix, int resultColumnsCount, int resultRowsCount, ref int[,] result)
        {
            int j1 = 0;
            for (int k = 0; k < resultColumnsCount; k++)
            {
                for (int i = 0; i < resultRowsCount; i++)
                {
                    int temp = 0;
                    int leno = (int)(firstMatrix.Length / Math.Sqrt(firstMatrix.Length));

                    for (int j = 0; j < firstMatrix.Length / Math.Sqrt(firstMatrix.Length); j++)
                    {
                        temp += firstMatrix[i, j] * secondMatrix[j, j1];
                    }
                    result[i, k] = temp;
                }
                j1++;
            }
            for (int i = 0; i < resultRowsCount; i++)
            {
                for (int j = 0; j < resultColumnsCount; j++)
                {
                    while (result[i, j] < 0)
                    {
                        result[i, j] += 26;
                    }
                    while (result[i, j] >= 26)
                    {
                        result[i, j] -= 26;
                    }
                }
            }
        }

        private void getNumbersCharacters(ref string cipherString, List<int> cipherList)
        {
            cipherString = "";
            char[] alphabet = new char[26];
            for (int i = 0; i < 26; i++)
                alphabet[i] = (char)(i + 65);
            for (int i = 0; i < cipherList.Count; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (cipherList[i] == j)
                        cipherString += alphabet[j];
                }
            }
        }

        private void getCharactersNumbers(ref List<int> plaintext, string plainstring1)
        {
            string plainstring = plainstring1.ToUpper();
            char[] alphabet = new char[26];
            for (int i = 0; i < 26; i++)
                alphabet[i] = (char)(i + 65);
            int length = plainstring.Count();
            for (int i = 0; i < length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (plainstring[i] == alphabet[j])
                        plaintext.Add(j);
                }

            }
        }

    }
}
