using System;
using System.Numerics;

namespace Cryptography
{
    public class RSA : Cryptography, ICipher
    {
        private RSAKey _key;

        public RSAKey Key
        {
            get { return _key; }
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
        }

        private BigInteger _e;

        public BigInteger E
        {
            get { return _e; }
        }

        private BigInteger _d;

        public BigInteger D
        {
            get { return _d; }
        }

        public RSA(RSAKey key)
        {
            _key = key;
            _n = BigInteger.Multiply(Key.P, Key.Q);
            _fi = BigInteger.Multiply(Key.P - 1, Key.Q - 1);
            _e = ReturnCoprimeNumber(_fi);
            _d = ComputeMultiplicativeInverse(_e, _fi);
        }

        public string encrypt(string plainText)
        {
            var foo = Cryptography.CodeText(plainText);
            var bar = new BigInteger[foo.Length];

            for (int i = 0; i < foo.Length; i++)
            {
                bar[i] = BigInteger.ModPow(foo[i], _e, _n);
            }
            return String.Join(" ", bar);
        }

        public string decrypt(string cipherText)
        {
            var foo = Array.ConvertAll<string, BigInteger>(cipherText.Split(' '), x => BigInteger.Parse(x));

            for (int i = 0; i < foo.Length; i++)
            {
                foo[i] = BigInteger.ModPow(foo[i], _d, _n);
            }
            return Cryptography.DecodeText(Array.ConvertAll<BigInteger, short>(foo, x => Int16.Parse(x.ToString())));
        }
    }

    public class RSAKey
    {
        public BigInteger P { get; private set; }

        public BigInteger Q { get; private set; }

        public RSAKey(BigInteger P, BigInteger Q)
        {
            if (!Cryptography.PrimalityTest(P))
                throw new ArgumentException("First argument is not a prime number. Only prime numbers are valid");
            if (!Cryptography.PrimalityTest(Q))
                throw new ArgumentException("Second argument is not a prime number. Only prime numbers are valid");
            this.P = P;
            this.Q = Q;
        }

        public RSAKey()
        {
            this.P = Cryptography.GenerateRandomPrimeNumber128b();
            this.Q = Cryptography.GenerateRandomPrimeNumber128b();
        }
    }
}