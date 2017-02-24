using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] + key > 122)
                    cipherText += (char)(plainText[i] + key - 97 + 65 - 26);
                else
                    cipherText += (char)(plainText[i] + key - 97 + 65);
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (cipherText[i] - key < 65)
                    plainText += (char)(cipherText[i] - key - 65 + 97 + 26);
                else
                    plainText += (char)(cipherText[i] - key - 65 + 97);
            }
            return plainText;
        }
        public int Analyse(string plainText, string cipherText)
        {
            bool keyNotFound = true;
            int key = 0;
            while (keyNotFound)
            {
                string temp = Encrypt(plainText, key);
                if (temp.Equals(cipherText))
                    keyNotFound = false;
                else
                    key++;
            }
            return key;
        }
    }
}
