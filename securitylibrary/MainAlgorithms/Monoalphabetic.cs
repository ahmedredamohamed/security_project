using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[] key = new char[26];
            for (int i = 0; i < plainText.Length; i++)
                key[plainText[i] - 97] = (char)(cipherText[i] + 32);

            for (int i = 0; i < 26; i++)
            {
                if (key[i].Equals('\0'))
                {
                    bool characterNotFound = true;
                    int ch = 97;
                    while (characterNotFound)
                    {
                        if (new string(key).IndexOf((char)ch) != -1)
                            ch++;
                        else
                        {
                            key[i] = (char)ch;
                            characterNotFound = false;
                        }
                    }
                }
            }
            return new string(key);
        }

        public string Decrypt(string cipherText, string key)
        {

            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
                plainText += (char)(key.IndexOf(cipherText[i].ToString().ToLower()) + 97);
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
                cipherText += key[plainText[i] - 97];
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            char[] key = new char[26];
            int[] temp = new int[26];
            string newCipher = cipher.ToLower();
            for (int i = 0; i < newCipher.Length; i++)
            {
                temp[newCipher[i] - 97]++;
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.1251)
                {
                    key['e' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {   if (((float)temp[i] / newCipher.Length) >= 0.0925 && ((float)temp[i] / newCipher.Length) < 0.1251)
                {
                    key['t' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {   if (((float)temp[i] / newCipher.Length) >= 0.0804 && ((float)temp[i] / newCipher.Length) < 0.0925)
                {
                    key['a' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.076 && ((float)temp[i] / newCipher.Length) < 0.0804)
                {
                    key['o' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0726 && ((float)temp[i] / newCipher.Length) < 0.076)
                {
                    key['i' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0709 && ((float)temp[i] / newCipher.Length) < 0.0726)
                {
                    key['n' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0654 && ((float)temp[i] / newCipher.Length) < 0.0709)
                {
                    key['s' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0612 && ((float)temp[i] / newCipher.Length) < 0.0654)
                {
                    key['r' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0549 && ((float)temp[i] / newCipher.Length) < 0.0612)
                {
                    key['h' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0414 && ((float)temp[i] / newCipher.Length) < 0.0549)
                {
                    key['l' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0399 && ((float)temp[i] / newCipher.Length) < 0.0414)
                {
                    key['d' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0306 && ((float)temp[i] / newCipher.Length) < 0.0399)
                {
                    key['c' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0271 && ((float)temp[i] / newCipher.Length) < 0.0306)
                {
                    key['u' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0253 && ((float)temp[i] / newCipher.Length) < 0.0271)
                {
                    key['m' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.023 && ((float)temp[i] / newCipher.Length) < 0.0253)
                {
                    key['f' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.02 && ((float)temp[i] / newCipher.Length) < 0.023)
                {
                    key['p' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0196 && ((float)temp[i] / newCipher.Length) < 0.02)
                {
                    key['g' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0192 && ((float)temp[i] / newCipher.Length) < 0.0196)
                {
                    key['w' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0173 && ((float)temp[i] / newCipher.Length) < 0.0192)
                {
                    key['y' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0154 && ((float)temp[i] / newCipher.Length) < 0.0173)
                {
                    key['b' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0099 && ((float)temp[i] / newCipher.Length) < 0.0154)
                {
                    key['v' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0067 && ((float)temp[i] / newCipher.Length) < 0.0099)
                {
                    key['k' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0019 && ((float)temp[i] / newCipher.Length) < 0.0067)
                {
                    key['x' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0016 && ((float)temp[i] / newCipher.Length) < 0.0019)
                {
                    key['j' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0011 && ((float)temp[i] / newCipher.Length) < 0.0016)
                {
                    key['q' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (((float)temp[i] / newCipher.Length) >= 0.0009 && ((float)temp[i] / newCipher.Length) < 0.0011)
                {
                    key['z' - 97] = (char)(i + 97);
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (key[i].Equals('\0'))
                {
                    bool characterNotFound = true;
                    int ch = 97;

                    while (characterNotFound)
                    {
                        if (new string(key).IndexOf((char)ch) != -1)
                            ch++;
                        else
                        {
                            key[i] = (char)ch;
                            characterNotFound = false;
                        }
                    }
                }
            }
            return Decrypt(cipher, new string(key));
        }
    }
}
