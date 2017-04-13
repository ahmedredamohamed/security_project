using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            if(GCD(number,baseN)!=1)
                return -1;
            int Inverse=0;
            
            return Inverse;
        }
        public static int GCD(int x, int y)
        {
            while (y != 0)
            {
                int z = x % y;
                x = y;
                y = z;
            }
            return x;
        }
    }
}
