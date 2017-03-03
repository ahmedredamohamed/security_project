using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;



namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            int j = 0;
            string plainText = "";
            string matrix = null;
            cipherText = cipherText.ToLower();
            string alphabetletters = "abcdefghiklmnopqrstuvwxyz";
            key = key.Replace('j', 'i');
            //fill matrix with key
            for (int i = 0; i < key.Length; i++)
                if ((matrix == null) || (!matrix.Contains(key[i])))
                    matrix += key[i];

            //fill matrix with alphabet if key finished

            for (int i = 0; i < alphabetletters.Length; i++)
                if (!matrix.Contains(alphabetletters[i]))
                    matrix += alphabetletters[i];
            while (j < cipherText.Length)
            {
                int FirstPosition = matrix.IndexOf(cipherText[j]);
                int SecondPosition = matrix.IndexOf(cipherText[j + 1]);
                int FirstRow = FirstPosition / 5;
                int SecondRow = SecondPosition / 5;
                int FirstColumn = FirstPosition % 5;
                int SecondCloumn = SecondPosition % 5;
                if (FirstColumn == SecondCloumn)
                {
                    FirstPosition -= 5;
                    SecondPosition -= 5;
                }
                else
                {
                    if (FirstRow == SecondRow)
                    {
                        if (FirstColumn == 0)
                            FirstPosition += 4;
                        else
                            FirstPosition -= 1;
                        if (SecondCloumn == 0)
                            SecondPosition += 4;
                        else
                            SecondPosition -= 1;
                    }
                    else
                    {
                        if (FirstRow < SecondRow)
                        {
                            FirstPosition -= FirstColumn - SecondCloumn;
                            SecondPosition += FirstColumn - SecondCloumn;

                        }

                        else
                        {
                            FirstPosition += SecondCloumn - FirstColumn;
                            SecondPosition -= SecondCloumn - FirstColumn;
                        }
                    }
                }
                if (FirstPosition < 0)
                    FirstPosition = matrix.Length + FirstPosition;
                if (SecondPosition < 0)
                    SecondPosition = matrix.Length + SecondPosition;

                plainText += matrix[FirstPosition].ToString() + matrix[SecondPosition].ToString();
                j += 2;
            }
            List<int> indecies = new List<int>();
            for (int i = 1; i < plainText.Length; i += 2)
                // gllnm ...gl lx nm (same letter)
                if (((i + 1) < plainText.Length) && (plainText[i - 1] == plainText[i + 1]) && (plainText[i] == 'x'))
                    indecies.Add(i);

            //bkgok ..bx go kx //lenght odd
            if (((plainText.Length % 2) == 0) && (plainText[plainText.Length - 1] == 'x'))
                plainText = plainText.Remove(plainText.Length - 1, 1);

            int count = 0;
            foreach (int i in indecies)
            {
                plainText = plainText.Remove(i - count, 1);
                count++;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            int j = 0;
            string chipertext = string.Empty;
            plainText = plainText.Replace('j', 'i');// replace i with j
            for (int i = 0; i < plainText.Length; i += 2)
                // gllnm ...gl lx nm (same letter)
                if (((i + 1) < plainText.Length) && (plainText[i] == plainText[i + 1]))
                    plainText = plainText.Insert(i + 1, "x");

            //bkgok ..bx go kx //lenght odd
            if ((plainText.Length % 2) == 1)
                plainText += "x";
            if ((plainText != "") && (key != ""))
            {
                string alphabetletters = "abcdefghiklmnopqrstuvwxyz";
                string matrix = null;
                key = key.Replace('j', 'i');

                //fill matrix with key
                for (int i = 0; i < key.Length; i++)
                    if ((matrix == null) || (!matrix.Contains(key[i])))
                        matrix += key[i];

                //fill matrix with alphabet if key finished

                for (int i = 0; i < alphabetletters.Length; i++)
                    if (!matrix.Contains(alphabetletters[i]))
                        matrix += alphabetletters[i];

                //get Row and Column of each character
                while (j < plainText.Length)
                {
                    int FirstPosition = matrix.IndexOf(plainText[j]);
                    int SecondPosition = matrix.IndexOf(plainText[j + 1]);
                    int FirstRow = FirstPosition / 5;
                    int SecondRow = SecondPosition / 5;
                    int FirstColumn = FirstPosition % 5;
                    int SecondCloumn = SecondPosition % 5;

                    if (FirstRow == SecondRow)
                    {
                        if (FirstColumn == 4)
                            FirstPosition -= 4;
                        else
                            FirstPosition += 1;
                        if (SecondCloumn == 4)
                            SecondPosition -= 4;
                        else
                            SecondPosition += 1;
                    }

                    else if (FirstColumn == SecondCloumn)
                    {
                        FirstPosition += 5;
                        SecondPosition += 5;
                    }
                    else
                    {
                        if (FirstRow > SecondRow)
                        {
                            FirstPosition += SecondCloumn - FirstColumn;
                            SecondPosition -= SecondCloumn - FirstColumn;
                        }

                        else
                        {
                            FirstPosition -= FirstColumn - SecondCloumn;
                            SecondPosition += FirstColumn - SecondCloumn;
                        }
                    }

                    if (FirstPosition >= matrix.Length)
                        FirstPosition = FirstPosition - matrix.Length;
                    if (SecondPosition >= matrix.Length)
                        SecondPosition = SecondPosition - matrix.Length;
                    chipertext += matrix[FirstPosition].ToString() + matrix[SecondPosition].ToString();
                    j += 2;
                }
            }
            return chipertext;
        }
    }
}