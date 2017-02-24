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
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            key = key.ToLower();
            plainText = plainText.ToLower();  
            int PositionNow = 0;
            string chipertext = string.Empty;
            Regex dictionary = new Regex("[^a-z-]");//specify a range with abcde.....like Dictionary
            plainText = dictionary.Replace(plainText, "");
            plainText = plainText.Replace('j', 'i');// replace i with j
            for (int g = 0; g < plainText.Length; g += 2)
            {
                // gllnm ...gl lx nm (same letter)
                if (((g + 1) < plainText.Length) && (plainText[g] == plainText[g + 1]))
                {
                    plainText = plainText.Insert(g + 1, "x");
                }
            }
            //bkgok ..bx go kx //lenght odd
            if ((plainText.Length % 2) > 0)
            {
                plainText += "x";
            }
            if ((plainText != "") && (key != ""))
            {
                string alphabetletters = "abcdefghiklmnopqrstuvwxyz";
                string charPosition = null;
                key = dictionary.Replace(key, ""); 
                key = key.Replace('j', 'i');
               
                //fill matrix with key
                for (int i = 0; i < key.Length; i++)
                {
                    if ((charPosition == null) || (!charPosition.Contains(key[i])))
                    {
                        charPosition += key[i];
                    }
                }
                //fill matrix with alphabet if key finished

                for (int i = 0; i < alphabetletters.Length; i++)
                {

                    if (!charPosition.Contains(alphabetletters[i]))
                    {

                        charPosition += alphabetletters[i];

                    }

                }

                 // string newpliantext = plainText.Replace(" ", "");
              //  plainText = newpliantext;
                /*
                for (int i = 0; i < plainText.Length; i++)
                {
                    plainText += plainText[i];

                    if (i < plainText.Length - 1 && plainText[i] == plainText[i + 1]) 
                    {
                        plainText = plainText.Insert(i+1,"x");
                    }
                }

                if (plainText.Length % 2 != 0)
                {
                    plainText += 'x';
                }

                */

                //get Row and Column of each character
                 while(PositionNow < plainText.Length)
                {
                    int PositionOne = charPosition.IndexOf(plainText[PositionNow]);
                    int PositionTwo = charPosition.IndexOf(plainText[PositionNow + 1]);
                    int FirstRow = PositionOne / 5;
                    int SecondRow = PositionTwo / 5;
                    int FirstColumn= PositionOne % 5;
                    int SecondCloumn = PositionTwo % 5;
                    if (PositionOne < 0)
                    {
                        PositionOne = charPosition.Length + PositionOne;
                    }
                    if (PositionTwo < 0)
                    {
                        PositionTwo = charPosition.Length + PositionTwo;
                    }
                     ////
                     if (FirstRow == SecondRow)
                        {
                            if (FirstColumn == 4)
                            {
                                PositionOne -= 4;
                            }
                            else
                            {
                                PositionOne += 1;
                            }

                            if (SecondCloumn == 4)
                            {
                                PositionTwo -= 4;
                            }

                            else
                            {
                                PositionTwo += 1;
                            }
                     }
                        //
                    else
                    {
                          if (FirstColumn == SecondCloumn)
                    {
                        PositionOne += 5;
                        PositionTwo += 5;
                    }
                        else
                          {
                            if (FirstRow > SecondRow)
                            {
                                PositionOne += SecondCloumn - FirstColumn;
                                PositionTwo -= SecondCloumn - FirstColumn;
                            }

                            else
                            {
                                PositionOne -= FirstColumn - SecondCloumn;
                                PositionTwo += FirstColumn - SecondCloumn;
                            }
                        }
                    }
                     if (PositionOne >= charPosition.Length)// same row
                     {
                         PositionOne = PositionOne - charPosition.Length;
                     }
                     if (PositionTwo >= charPosition.Length)
                     {
                         PositionTwo = PositionTwo - charPosition.Length;
                     }
                    chipertext += charPosition[PositionOne].ToString() + charPosition[PositionTwo].ToString();
                    PositionNow += 2;
                }
            }
            return chipertext;
        }
    }
}