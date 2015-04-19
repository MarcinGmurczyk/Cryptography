using System;
using System.Numerics;

namespace Cryptography
{
    public class AffineCipher : ICipher
    {
        public AffineCipherKey Key { get; private set; }

        public AffineCipher(AffineCipherKey key)
        {
            Key = key;
        }

        public string Encrypt(string plainText)
        {
            var mod = Cryptography.CharToShortTable.Count;
            var foo = Cryptography.CodeText(plainText);
            BigInteger temp;

            for (var i = 0; i < plainText.Length; i++)
            {
                temp = BigInteger.Multiply(Key.A, foo[i]);
                temp = BigInteger.Add(temp, Key.B);
                foo[i] = (short)Cryptography.Modulus(temp, mod);
            }
            return Cryptography.DecodeText(foo);
        }

        public string Decrypt(string cipherText)
        {
            var mod = Cryptography.CharToShortTable.Count;
            var multInverse = Cryptography.ComputeMultiplicativeInverse(Key.A, mod);
            var codedText = Cryptography.CodeText(cipherText);
            BigInteger temp;

            for (var i = 0; i < cipherText.Length; i++)
            {
                temp = BigInteger.Multiply(multInverse, codedText[i] - Key.B);
                codedText[i] = (short)Cryptography.Modulus(temp, mod);
            }
            return Cryptography.DecodeText(codedText);
        }

        public override string ToString()
        {
            return "(" + Key.A + ", " + Key.B + ")";
        }
    }

    public class AffineCipherKey
    {
        public short A { get; private set; }

        public short B { get; private set; }

        public AffineCipherKey(short valueA, short valueB)
        {
            if (!Array.Exists(Cryptography.CoprimeNumbersTable(Cryptography.ShortToCharTable.Count), x => x == valueA))
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
            B = (short)Cryptography.RandomBigInteger(1, Cryptography.CharToShortTable.Count + 1);
        }
    }
}