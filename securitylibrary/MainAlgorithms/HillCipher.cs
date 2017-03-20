using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Complex;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            double[,] plainMatrix;
            double[,] cipherMatrix;
            int matrixSize = 2;
            plainMatrix = new double[matrixSize, matrixSize];
            cipherMatrix = new double[matrixSize, matrixSize];
            List<int> keyList = new List<int>();
            addKeyListInMatrix(plainText, ref plainMatrix, matrixSize);
            addKeyListInMatrix(cipherText, ref cipherMatrix, matrixSize);
            double[,] palinInverse = inverseMatrix(plainMatrix);//nonrevirsible error
            while(palinInverse==null)
            {
                plainText.RemoveRange(0, 2);
                cipherText.RemoveRange(0, 2);
                if(plainText.Count<4||cipherText.Count<4)
                {
                    throw new InvalidAnlysisException();
                }
                addKeyListInMatrix(plainText, ref plainMatrix, matrixSize);
                addKeyListInMatrix(cipherText, ref cipherMatrix, matrixSize);
                palinInverse = inverseMatrix(plainMatrix);//nonrevirsible error
            }
            Matrix<double> keyMatix = Matrix<double>.Build.Random(matrixSize, matrixSize);
            Matrix<double>.Build.DenseOfArray(palinInverse).Multiply(Matrix<double>.Build.DenseOfArray(cipherMatrix), keyMatix);

            addKeyMatrixtoList(ref keyList,keyMatix,matrixSize);
            return keyList;
        }

        
        public string Analyse(string plainText, string cipherText)
        {
            List<int> cipherList = new List<int>();
            cipherText = cipherText.ToLower();
            List<int> plainList = new List<int>();
            plainText = plainText.ToLower();
            List<int> keyList = new List<int>();

            getCharactersIntValues(ref cipherList, cipherText);
            getCharactersIntValues(ref plainList, plainText);

            keyList = Analyse(plainList, cipherList);


            string keyString = "";
            getIntValuesCharacters(ref keyString, keyList);

            return keyString;

        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            double[,] keyMatrix;
            double[,] cipherMatrix;
            int matrixSize;
            if (key.Count % 2 != 0)
                matrixSize = 3;
            else
                matrixSize = 2;
            keyMatrix = new double[matrixSize, matrixSize];
            cipherMatrix = new double[matrixSize, cipherText.Count / matrixSize];
            List<int> plainList = new List<int>();
            addKeyListInMatrix(key, ref keyMatrix, matrixSize);
            addPlainOrCipherListInMatrix(cipherText, ref cipherMatrix, matrixSize, cipherText.Count / matrixSize);

            double[,] keyInverse = inverseMatrix(keyMatrix);
            if (keyInverse == null)
                throw new System.Exception();

            Matrix<double> plainMatrix = Matrix<double>.Build.Random(matrixSize, cipherText.Count / matrixSize);
            Matrix<double>.Build.DenseOfArray(keyInverse).Multiply(Matrix<double>.Build.DenseOfArray(cipherMatrix), plainMatrix);

            addPlainOrCipherMatrixToList(ref plainList, plainMatrix, matrixSize, cipherText.Count / matrixSize);

            return plainList;
        }

        public string Decrypt(string cipherText, string key)
        {
            List<int> cipherTextList = new List<int>();
            cipherText = cipherText.ToLower();
            List<int> keyList = new List<int>();
            List<int> plainList = new List<int>();
            string plainString = "";
            cipherText = cipherText.ToLower();

            getCharactersIntValues(ref cipherTextList, cipherText);
            getCharactersIntValues(ref keyList, key);

            plainList = Decrypt(cipherTextList, keyList);

            getIntValuesCharacters(ref plainString, plainList);

            return plainString;
            //throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            double[,] keyMatrix;
            double[,] plainMatrix;

            int matrixSize;
            if (key.Count % 2 == 0)
                matrixSize = 2;
            else
                matrixSize = 3;

            keyMatrix = new double[matrixSize, matrixSize];
            plainMatrix = new double[matrixSize, plainText.Count / matrixSize];
            List<int> cipherList = new List<int>();

            addKeyListInMatrix(key, ref keyMatrix, matrixSize);
            addPlainOrCipherListInMatrix(plainText, ref plainMatrix, matrixSize, plainText.Count / matrixSize);

            Matrix<double> cipherMatrix = Matrix<double>.Build.Random(matrixSize, plainText.Count / matrixSize);
            Matrix<double>.Build.DenseOfArray(keyMatrix).Multiply(Matrix<double>.Build.DenseOfArray(plainMatrix), cipherMatrix);


            addPlainOrCipherMatrixToList(ref cipherList, cipherMatrix, matrixSize, plainText.Count / matrixSize);
            return cipherList;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            List<int> plainTextList = new List<int>();
            List<int> keyList = new List<int>();
            List<int> cipherList = new List<int>();
            string cipherString = "";

            getCharactersIntValues(ref plainTextList, plainText);
            getCharactersIntValues(ref keyList, key);

            cipherList = Encrypt(plainTextList, keyList);

            getIntValuesCharacters(ref cipherString, cipherList);
            return cipherString;
            //throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            double[,] plainMatrix;
            double[,] cipherMatrix;
            int matrixSize = 3;
            plainMatrix = new double[matrixSize, matrixSize];
            cipherMatrix = new double[matrixSize, matrixSize];
            List<int> keyList = new List<int>();
            addKeyListInMatrix(plain3, ref plainMatrix, matrixSize);
            addKeyListInMatrix(cipher3, ref cipherMatrix, matrixSize);

            double[,] palinInverse = inverseMatrix(plainMatrix);//nonrevirsible error
            while (palinInverse == null)
            {
                plain3.RemoveRange(0, 3);
                cipher3.RemoveRange(0, 3);
                if (plain3.Count < 9 || cipher3.Count < 9)
                {
                    throw new InvalidAnlysisException();
                }
                addKeyListInMatrix(plain3, ref plainMatrix, matrixSize);
                addKeyListInMatrix(cipher3, ref cipherMatrix, matrixSize);
                palinInverse = inverseMatrix(plainMatrix);//nonrevirsible error
            }

            Matrix<double> keyMatix = Matrix<double>.Build.Random(matrixSize, matrixSize);
            Matrix<double>.Build.DenseOfArray(palinInverse).Multiply(Matrix<double>.Build.DenseOfArray(cipherMatrix), keyMatix);

            addKeyMatrixtoList(ref keyList, keyMatix, matrixSize);
            return keyList;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            List<int> cipherList = new List<int>();
            cipher3 = cipher3.ToLower();
            List<int> plainList = new List<int>();
            plain3 = plain3.ToLower();
            List<int> keyList = new List<int>();

            getCharactersIntValues(ref cipherList, cipher3);
            getCharactersIntValues(ref plainList, plain3);

            keyList = Analyse3By3Key(plainList, cipherList);


            string keyString = "";
            getIntValuesCharacters(ref keyString, keyList);

            return keyString;


        }

        private void addKeyListInMatrix(List<int> keyList, ref double[,] keyMatrix, int matrixSize)
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

        private void addKeyMatrixtoList(ref List<int> List, Matrix<double> Matrix, int matrixSize)
        {
            for (int i = 0; i < matrixSize; i++)
            {
                for (int j = 0; j < matrixSize; j++)
                    List.Add(Convert.ToInt32(Matrix[j, i] % 26));

            }
        }

        private void addPlainOrCipherListInMatrix(List<int> plainList, ref double[,] plainMatrix, int numOfRows, int numOfCoulmns)
        {
            int plainTextListIndex = 0;
            for (int i = 0; i < numOfCoulmns; i++)
            {
                for (int j = 0; j < numOfRows; j++)
                {
                    plainMatrix[j, i] = plainList[plainTextListIndex];
                    plainTextListIndex++;
                }
            }
        }

        private void addPlainOrCipherMatrixToList(ref List<int> List, Matrix<double> Matrix, int numOfRows, int numOfCoulmns)
        {
            for (int i = 0; i < numOfCoulmns; i++)
            {
                for (int j = 0; j < numOfRows; j++)
                    List.Add(Convert.ToInt32(Matrix[j, i] % 26));

            }
        }

        private void getIntValuesCharacters(ref string text, List<int> intTextList)
        {
            for (int i = 0; i < intTextList.Count; i++)
            {
                text += (Convert.ToChar(intTextList[i] + 97)).ToString();
            }
        }

        private void getCharactersIntValues(ref List<int> intTextList, string text)
        {
            for (int i = 0; i < text.Length; i++)
                intTextList.Add(text[i] - 'a');
        }

        private double[,] inverseMatrix(double[,] matrix)
        {
            int size = matrix.GetLength(0);
            double det = Matrix<double>.Build.DenseOfArray(matrix).Determinant();

            if (det > -1)
                det = det % 26;
            else // In case of negative det
                det = handleNegativeDet(Convert.ToInt32(det));

            int inverseDet = 0;
            bool isInversable = CalculateDetInverse(ref inverseDet, Convert.ToInt32(det), 26);
            if (!isInversable)
                return null;
            double[,] cofactorMatrix = new double[size, size];
            cofactorMatrix = calculateCofactor(matrix, size);

            cofactorMatrix = Matrix<double>.Build.DenseOfArray(cofactorMatrix).Transpose().Multiply(inverseDet).ToArray();

            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    if (cofactorMatrix[i, j] > -1)
                        cofactorMatrix[i, j] = cofactorMatrix[i, j] % 26;
                    else
                        cofactorMatrix[i, j] = handleNegativeDet(Convert.ToInt32(cofactorMatrix[i, j]));
                }
            }
            return cofactorMatrix;
        }

        private int handleNegativeDet(int det)
        {
            while (det < 0)
                det += 26;

            return det;
        }

        private double[,] calculateCofactor(double[,] keyMatrix, int size)
        {
            double[,] cofactorMatrix = new double[size, size];
            if (size == 2)
            {
                cofactorMatrix[0, 0] = keyMatrix[1, 1]; cofactorMatrix[0, 1] = -keyMatrix[1, 0];
                cofactorMatrix[1, 0] = -keyMatrix[0, 1]; cofactorMatrix[1, 1] = keyMatrix[0, 0];
            }
            else
            {
                cofactorMatrix[0, 0] = keyMatrix[1, 1] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 1];
                cofactorMatrix[0, 1] = -(keyMatrix[1, 0] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 0]);
                cofactorMatrix[0, 2] = (keyMatrix[1, 0] * keyMatrix[2, 1] - keyMatrix[1, 1] * keyMatrix[2, 0]);

                cofactorMatrix[1, 0] = -(keyMatrix[0, 1] * keyMatrix[2, 2] - keyMatrix[0, 2] * keyMatrix[2, 1]);
                cofactorMatrix[1, 1] = (keyMatrix[0, 0] * keyMatrix[2, 2] - keyMatrix[0, 2] * keyMatrix[2, 0]);
                cofactorMatrix[1, 2] = -(keyMatrix[0, 0] * keyMatrix[2, 1] - keyMatrix[0, 1] * keyMatrix[2, 0]);

                cofactorMatrix[2, 0] = (keyMatrix[0, 1] * keyMatrix[1, 2] - keyMatrix[0, 2] * keyMatrix[1, 1]);
                cofactorMatrix[2, 1] = -(keyMatrix[0, 0] * keyMatrix[1, 2] - keyMatrix[0, 2] * keyMatrix[1, 0]);
                cofactorMatrix[2, 2] = (keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[1, 0] * keyMatrix[0, 1]);
            }

            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    if (cofactorMatrix[i, j] > -1)
                        cofactorMatrix[i, j] = cofactorMatrix[i, j] % 26;
                    else
                        cofactorMatrix[i, j] = handleNegativeDet(Convert.ToInt32(cofactorMatrix[i, j]));
                }
            }

            return cofactorMatrix;
        }

        private bool CalculateDetInverse(ref int inv, int det, int baseNumber)
        {
            int a1 = 1, a2 = 0, a3 = baseNumber, b1 = 0, b2 = 1, b3 = det;
            while (true)
            {
                if (b3 == 0)
                    return false;

                else if (b3 == 1)
                {
                    inv = b2;
                    if (inv > -1)
                        inv = inv % 26;
                    else
                        inv = handleNegativeDet(inv);
                    return true;
                }
                int q = a3 / b3;
                int t1 = a1 - q * b1, t2 = a2 - q * b2, t3 = a3 - q * b3;
                a1 = b1; a2 = b2; a3 = b3;
                b1 = t1; b2 = t2; b3 = t3;
            }
        }

    }
}
