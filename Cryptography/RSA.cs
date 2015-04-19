using System;
using System.Numerics;
// ReSharper disable All

namespace Cryptography
{
    public class RSA : ICipher
    {
        public RSAKey Key { get; private set; }

        public RSA(RSAKey key)
        {
            Key = key;
        }

        public string GetPrivateKey()
        {
            return "(" + Key.D + ", " + Key.N + ")";
        }

        public string GetPublicKey()
        {
            return "(" + Key.E + ", " + Key.N + ")";
        }

        public string Encrypt(string plainText)
        {
            var codedText = Cryptography.CodeText(plainText);
            var encodedTable = new BigInteger[codedText.Length];

            for (var i = 0; i < codedText.Length; i++)
            {
                encodedTable[i] = BigInteger.ModPow(codedText[i], Key.E, Key.N);
            }
            return string.Join(" ", encodedTable);
        }

        public string Decrypt(string cipherText)
        {
            var encodedTable = Array.ConvertAll(cipherText.Split(' '), BigInteger.Parse);

            for (var i = 0; i < encodedTable.Length; i++)
            {
                encodedTable[i] = BigInteger.ModPow(encodedTable[i], Key.D, Key.N);
            }
            return Cryptography.DecodeText(Array.ConvertAll(encodedTable, x => Int16.Parse(x.ToString())));
        }
    }

    public class RSAKey
    {
        public BigInteger D { get; private set; }

        public BigInteger E { get; private set; }

        public BigInteger N { get; private set; }

        public RSAKey(BigInteger p, BigInteger q)
        {
            if (!Cryptography.PrimalityTest(p))
                throw new ArgumentException("First argument is not a prime number. Only prime numbers are valid");
            if (!Cryptography.PrimalityTest(q))
                throw new ArgumentException("Second argument is not a prime number. Only prime numbers are valid");

            N = BigInteger.Multiply(p, q);
            var fi = BigInteger.Multiply(p - 1, q - 1);
            E = Cryptography.ReturnCoprimeNumber(fi);
            D = Cryptography.ComputeMultiplicativeInverse(E, fi);
        }

        public RSAKey()
            : this(Cryptography.GenerateRandomPrimeNumber128b(), Cryptography.GenerateRandomPrimeNumber128b()) { }
    }
}