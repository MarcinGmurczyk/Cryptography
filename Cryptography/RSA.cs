using System;
using System.Numerics;

namespace Cryptography
{
    public class RSA : ICipher
    {
        private RSAKey _key;

        public RSAKey Key
        {
            get { return _key; }
        }
        public RSA(RSAKey key)
        {
            _key = key;
        }

        public string GetPrivateKey()
        {
            return "(" + _key.D + ", " + _key.N + ")";
        }

        public string GetPublicKey()
        {
            return "(" + _key.E + ", " + _key.N + ")";
        }

        public string Encrypt(string plainText)
        {
            var codedText = Cryptography.CodeText(plainText);
            var encodedTable = new BigInteger[codedText.Length];

            for (int i = 0; i < codedText.Length; i++)
            {
                encodedTable[i] = BigInteger.ModPow(codedText[i], _key.E, _key.N);
            }
            return String.Join(" ", encodedTable);
        }

        public string Decrypt(string cipherText)
        {
            var encodedTable = Array.ConvertAll<string, BigInteger>(cipherText.Split(' '), x => BigInteger.Parse(x));

            for (int i = 0; i < encodedTable.Length; i++)
            {
                encodedTable[i] = BigInteger.ModPow(encodedTable[i], _key.D, _key.N);
            }
            return Cryptography.DecodeText(Array.ConvertAll<BigInteger, short>(encodedTable, x => Int16.Parse(x.ToString())));
        }
    }

    public class RSAKey
    {
        public BigInteger D { get; private set; }

        public BigInteger E { get; private set; }

        public BigInteger N { get; private set; }

        public RSAKey(BigInteger P, BigInteger Q)
        {
            if (!Cryptography.PrimalityTest(P))
                throw new ArgumentException("First argument is not a prime number. Only prime numbers are valid");
            if (!Cryptography.PrimalityTest(Q))
                throw new ArgumentException("Second argument is not a prime number. Only prime numbers are valid");

            N = BigInteger.Multiply(P, Q);
            var fi = BigInteger.Multiply(P - 1, Q - 1);
            E = Cryptography.ReturnCoprimeNumber(fi);
            D = Cryptography.ComputeMultiplicativeInverse(E, fi);
        }
        public RSAKey()
            : this(Cryptography.GenerateRandomPrimeNumber128b(), Cryptography.GenerateRandomPrimeNumber128b()) {}        
    }
}