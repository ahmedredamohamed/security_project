using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int YA = 1;
            int YB = 1;
            int key_1 = 1;
            int key_2 = 1;
            List<int> Keys = new List<int>();
            for (int i = 0; i < xa; i++)
            {
                YA *= (int)(Math.Pow(alpha, 1) % q);
                if (YA > q)
                    YA %= q;
            }
            for (int i = 0; i < xb; i++)
            {
                YB *= (int)(Math.Pow(alpha, 1) % q);
                if (YB > q)
                    YB %= q;
            }
            for (int i = 0; i < xb; i++)
            {
                key_1 *= (int)(Math.Pow(YA, 1) % q);
                if (key_1 > q)
                    key_1 %= q;
            }
            Keys.Add(key_1);
            for (int i = 0; i < xa; i++)
            {
                key_2 *= (int)(Math.Pow(YB, 1) % q);
                if (key_2 > q)
                    key_2 %= q;
            }
            Keys.Add(key_2);
            return Keys;
        }
    }
}
