using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q ;
            int result = 1;
            for (int i = 0; i < e; i++) {
                result *= (int)(Math.Pow(M, 1) % n);
                while (result > n)
                    result %= n;
            }
            return result;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int totient = (p - 1) * (q - 1);
            List<int> Q = new List<int>();
            List<int> A1 = new List<int>();
            List<int> A2 = new List<int>();
            List<int> A3 = new List<int>();
            List<int> B1 = new List<int>();
            List<int> B2 = new List<int>();
            List<int> B3 = new List<int>();
            int result = 1;
            Q.Add(0);
            A1.Add(1);
            A2.Add(0);
            A3.Add(totient);
            B1.Add(0);
            B2.Add(1);
            B3.Add(e);
            while (!B3.Contains(1))
            {
                Q.Add(A3.Last() / B3.Last());
                A1.Add(B1.Last());
                A2.Add(B2.Last());
                A3.Add(B3.Last());
                B1.Add(A1.ElementAt(A1.Count() - 2) - (Q.Last() * B1.ElementAt(B1.Count() - 1)));
                B2.Add(A2.ElementAt(A2.Count() - 2) - (Q.Last() * B2.ElementAt(B2.Count() - 1)));
                B3.Add(A3.ElementAt(A3.Count() - 2) - (Q.Last() * B3.ElementAt(B3.Count() - 1)));
            }
            int d = B2.Last();
            while (d < 0)
                d += totient;
            for (int i = 0; i < d; i++)
            {
                result *= (int)(Math.Pow(C, 1) % n);
                while (result > n)
                    result %= n;
            }
            return result;
        }
    }
}
