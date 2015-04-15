using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace Crypto
{
    class RSA: Cryptography, ICipher
    {
        private BigInteger _p;

        public BigInteger P
        {
            get { return _p; }
            set { _p = value; }
        }

        private BigInteger _q;

        public BigInteger Q
        {
            get { return _q; }
            set { _q = value; }
        }

        private BigInteger _n;

        public BigInteger N
        {
            get { return _n; }
        }

        private BigInteger _fi;

        public BigInteger Fi
        {
            get { return _fi; }
            set { _fi = value; }
        }

        private BigInteger _e;

        public BigInteger E
        {
            get { return _e; }
            set { _e = value; }
        }

        private BigInteger _d;

        public BigInteger D
        {
            get { return _d; }
            set { _d = value; }
        }

        public RSA(BigInteger P, BigInteger Q)
        {
            _p = P;
            _q = Q;
            _n = BigInteger.Multiply(_p, _q);
            _fi = BigInteger.Multiply(_p - 1, _q - 1);
            _e = ReturnCoprimeNumber(_fi);
            _d = ComputeMultiplicativeInverse(_e, _fi);
        }

        public string encrypt(string plainText)
        {
            var foo = Cryptography.CodeText(plainText);
            var temp = new BigInteger();

            for (int i = 0; i < plainText.Length; i++)
            {

            }
            return Cryptography.DecodeText(foo);
        }

        public string decrypt(string CipherText)
        {
            throw new NotImplementedException();
        }
    }
}
