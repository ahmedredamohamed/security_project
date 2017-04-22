using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            int j = 0;
            int i = 0;
            bool hexa = false;
            string temp = "";
            if (cipherText[0] == '0' && cipherText[1] == 'x')
            {
                hexa = true;
                string h;

                for (i = 2; i < cipherText.Length; i += 2)
                {
                    h = "00";
                    h += cipherText[i];
                    h += cipherText[i + 1];
                    char cha = (char)Int16.Parse(h, NumberStyles.AllowHexSpecifier);
                    temp += cha;
                }
                cipherText = temp;
                temp = "";
                for (i = 2; i < key.Length; i += 2)
                {
                    h = "00";
                    h += key[i];
                    h += key[i + 1];
                    char cha = (char)Int16.Parse(h, NumberStyles.AllowHexSpecifier);
                    temp += cha;
                }
                key = temp;

            }

            int[] S = new int[256];
            for (i = 0; i < 256; i++)
            {
                S[i] = i;
            }
            int[] T = new int[256];

            while (j < 256)
            {
                for (i = 0; i < key.Length; i++, j++)
                {
                    if (j == 256)
                        break;
                    T[j] = key[i];

                }
            }
            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                swap(ref S[i], ref S[j]);
            }
            i = 0;
            j = 0;
            int l = 0;
            int t;
            int[] k = new int[cipherText.Length];
            while (l < cipherText.Length)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                swap(ref S[i], ref S[j]);
                t = (S[i] + S[j]) % 256;
                k[l] = S[t];
                l++;
            }
            l = 0;
            int[] p = new int[cipherText.Length];
            foreach (char ch in cipherText)
            {
                p[l] = Convert.ToInt32(ch);
                l++;
            }
            int[] c = new int[cipherText.Length];
            for (i = 0; i < cipherText.Length; i++)
            {
                c[i] = p[i] ^ k[i];
            }
            if (hexa == true)
            {
                string hexastring = "0x";
                foreach (var integer in c)
                {
                    string hexavalue = integer.ToString("X");
                    hexastring += hexavalue;
                }

                return hexastring;
            }
            string s = "";
            foreach (var ic in c)
            {
                s += (char)ic;
            }
            return s;
        }

        public override string Encrypt(string plainText, string key)
        {
            int j = 0;
            int i = 0;
            string temp = "";
            bool hexa = false;
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                hexa = true;
                string h;
                for (i = 2; i < plainText.Length; i += 2)
                {
                    h = "00";
                    h += plainText[i];
                    h += plainText[i + 1];
                    char cha = (char)Int16.Parse(h, NumberStyles.AllowHexSpecifier);
                    temp += cha;
                }
                plainText = temp;
                temp = "";
                for (i = 2; i < key.Length; i += 2)
                {
                    h = "00";
                    h += key[i];
                    h += key[i + 1];
                    char cha = (char)Int16.Parse(h, NumberStyles.AllowHexSpecifier);
                    temp += cha;
                }
                key = temp;
            }


            int[] S = new int[256];
            for (i = 0; i < 256; i++)
            {
                S[i] = i;
            }
            int[] T = new int[256];

            while (j < 256)
            {
                for (i = 0; i < key.Length; i++, j++)
                {
                    if (j == 256)
                        break;
                    T[j] = key[i];

                }
            }
            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                swap(ref S[i], ref S[j]);
            }
            i = 0;
            j = 0;
            int l = 0;
            int t;
            int[] k = new int[plainText.Length];
            while (l < plainText.Length)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                swap(ref S[i], ref S[j]);
                t = (S[i] + S[j]) % 256;
                k[l] = S[t];
                l++;
            }
            l = 0;
            int[] p = new int[plainText.Length];
            foreach (char ch in plainText)
            {
                p[l] = Convert.ToInt32(ch);
                l++;
            }
            int[] c = new int[plainText.Length];
            for (i = 0; i < plainText.Length; i++)
            {
                c[i] = p[i] ^ k[i];
            }
            if (hexa == true)
            {
                string hexastring = "0x";
                foreach (var integer in c)
                {
                    string hexavalue = integer.ToString("X");
                    hexastring += hexavalue;
                }

                return hexastring;
            }
            string s = "";
            foreach (var ic in c)
            {
                s += (char)ic;
            }
            return s;
        }

        private void swap(ref int v1, ref int v2)
        {
            int temp;
            temp = v1;
            v1 = v2;
            v2 = temp;
        }
    }
}
