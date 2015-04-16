using System;
using System.Numerics;

namespace Crypto
{
    public class AffineCipher : Cryptography, ICipher
    {
        private AffineCipherKey _key;

        public AffineCipherKey Key
        {
            get { return _key; }
        }

        private string _decryptedText;

        public string DecryptedText
        {
            get { return _decryptedText; }
            private set { _decryptedText = value; }
        }

        private string _encryptedText;

        public string EncryptedText
        {
            get { return _encryptedText; }
            private set { _encryptedText = value; }
        }

        public AffineCipher(AffineCipherKey key)
        {
            _key = key;
        }

        public string encrypt(string plainText)
        {
            var mod = Cryptography.CharToShortTable.Count;
            var foo = Cryptography.CodeText(plainText);
            var temp = new BigInteger();

            for (int i = 0; i < plainText.Length; i++)
            {
                temp = BigInteger.Multiply(_key.A, foo[i]);
                temp = BigInteger.Add(temp, _key.B);
                foo[i] = (short)Modulus(temp, mod);
            }
            return Cryptography.DecodeText(foo);
        }

        public string decrypt(string cipherText)
        {
            var mod = Cryptography.CharToShortTable.Count;
            var multInverse = Cryptography.ComputeMultiplicativeInverse(_key.A, mod);
            var foo = Cryptography.CodeText(cipherText);
            BigInteger temp;

            for (int i = 0; i < cipherText.Length; i++)
            {
                temp = BigInteger.Multiply(multInverse, foo[i] - _key.B);
                foo[i] = (short)Modulus(temp, mod);
            }
            return Cryptography.DecodeText(foo);
        }
    }

    public class AffineCipherKey
    {
        public short A { get; private set; }

        public short B { get; private set; }

        public AffineCipherKey(short valueA, short valueB)
        {
            if (!Array.Exists<BigInteger>(Cryptography.CoprimeNumbersTable(Cryptography.ShortToCharTable.Count), x =>
            {
                if (x == valueA)
                    return true;
                else
                    return false;
            }))
            {
                throw new ArgumentException("value A has to be coprime with a mod number(mod = " + Cryptography.ShortToCharTable.Count + ")");
            }

            if (valueB > Cryptography.ShortToCharTable.Count || valueB < 1)
            {
                throw new ArgumentException("value B has to be greater than 0 and smaller than mod number(mod = " + Cryptography.ShortToCharTable.Count + ")");
            }

            A = valueA;
            B = valueB;
        }

        public AffineCipherKey()
        {
            A = (short)Cryptography.ReturnCoprimeNumber(Cryptography.CharToShortTable.Count);
            B = (short)Cryptography._rand.Next(1, Cryptography.CharToShortTable.Count + 1);
        }
    }
}