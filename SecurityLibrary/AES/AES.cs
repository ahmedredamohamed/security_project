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
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public byte[][] subbytes(byte[][] state)
        {
            for(int i=0;i<state.GetLength(0);i++)
            {
                for(int j=0;i<state.GetLength(1);j++)
                {
                    byte temp=state[i][j];
                }
            }
            return state;
        }
    }
}
