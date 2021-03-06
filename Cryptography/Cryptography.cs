﻿using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

// ReSharper disable All

namespace Cryptography
{
    public abstract class Cryptography
    {
        private readonly static Dictionary<char, short> _charToShortTable;
        private static readonly Dictionary<short, char> _shortToCharTable;

        static Cryptography()
        {
            //fulfilling code table
            _charToShortTable = new Dictionary<char, short>();
            _shortToCharTable = new Dictionary<short, char>();

            _charToShortTable.Add(' ', 0);
            _shortToCharTable.Add(0, ' ');

            _charToShortTable.Add('\n', 1);
            _shortToCharTable.Add(1, '\n');

            _charToShortTable.Add('\r', 2);
            _shortToCharTable.Add(2, '\r');

            _charToShortTable.Add('\t', 3);
            _shortToCharTable.Add(3, '\t');

            for (short i = 33; i <= 126; i++)
            {
                _charToShortTable.Add((char)i, (short)(i - 29));
                _shortToCharTable.Add((short)(i - 29), (char)i);
            }

            for (short i = 161; i <= 500; i++)
            {
                _charToShortTable.Add((char)i, (short)(i - 63));
                _shortToCharTable.Add((short)(i - 63), (char)i);
            }
        }

        //public static int Random(int min, int max)
        //{
        //    return _rand.Next(min, max);
        //}

        public static Dictionary<char, short> CharToShortTable
        {
            get { return _charToShortTable; }
        }

        public static Dictionary<short, char> ShortToCharTable
        {
            get { return _shortToCharTable; }
        }

        /// <summary>
        /// Miller–Rabin primality test
        /// http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
        /// </summary>
        /// <param name="number">Tested number</param>
        /// <param name="iterations">Number of iterations, default value is 20. It gives probability of 1 to 1099511627776 valid test results</param>
        /// <returns></returns>
        public static bool PrimalityTest(BigInteger number, long iterations = 20) //test, TestPrimalityFunction
        {
            if (number == 2 || number == 3)
                return true;

            if (number < 2 || BigInteger.Remainder(number, 2) == 0)
                return false;

            var d = number - 1;
            long s = 0;

            while (d % 2 == 0)
            {
                s++;
                d /= 2;
            }

            BigInteger a;
            BigInteger x;

            for (var i = 0; i < iterations; i++)
            {
                a = RandomBigInteger(2, number - 2);
                x = BigInteger.ModPow(a, d, number);
                if (x == 1 || x == number - 1)
                    continue;
                var j = 1;
                while (j < s && x != number - 1)
                {
                    x = BigInteger.ModPow(x, 2, number);
                    if (x == 1)
                    {
                        return false;
                    }
                    j++;
                }
                if (x != number - 1)
                {
                    return false;
                }
            }
            return true;
        }

        public static BigInteger RandomBigInteger(BigInteger min, BigInteger max)
        {
            return (Random128b() % (max - min)) + min;
        }

        public static BigInteger Random128b()
        {
            using (var RNGCryptoRandomizer = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[16];
                RNGCryptoRandomizer.GetBytes(bytes);
                return BigInteger.Abs(new BigInteger(bytes));
            }
        }

        /// <summary>
        /// Generates random prime number of 128bits length
        /// </summary>
        /// <returns></returns>
        public static BigInteger GenerateRandomPrimeNumber128b()
        {
            var number = Random128b();
            while (PrimalityTest(number) == false)
            {
                number++;
            }
            return number;
        }

        public static short[] CodeText(string plainText)
        {
            var codedText = new short[plainText.Length];
            for (var i = 0; i < plainText.Length; i++)
            {
                _charToShortTable.TryGetValue(plainText[i], out codedText[i]);
            }
            return codedText;
        }

        public static string DecodeText(short[] codedText)
        {
            var decodedText = new StringBuilder();

            for (var i = 0; i < codedText.Length; i++)
            {
                decodedText.Append(_shortToCharTable[codedText[i]]);
            }

            return decodedText.ToString();
        }

        /// <summary>
        /// Function computes Multiplicative Inverse (a^-1 mod b)
        /// </summary>
        /// <param name="a">param a in equation</param>
        /// <param name="b">param b in equation</param>
        /// <returns>Multiplicative inverse of expresion (a^-1 mod b) or returns -1 if multiplicative inverse is not present</returns>
        public static BigInteger ComputeMultiplicativeInverse(BigInteger a, BigInteger b)//test, MultiplicativeInverse
        {
            BigInteger u = 1, x = 0,
                        w = a, z = b, q = 0;

            while (w != 0)
            {
                if (w < z)
                {
                    var temp = u;
                    u = x;
                    x = temp;

                    var temp2 = w;
                    w = z;
                    z = temp2;
                }
                q = BigInteger.Divide(w, z);
                u = u - BigInteger.Multiply(q, x);
                w = w - BigInteger.Multiply(q, z);
            }
            if (z != 1)
                return -1;
            if (x < 0)
                x = x + b;
            return x;
        }

        /// <summary>
        /// Returns table of comprime numbers to given 'a' number
        /// </summary>
        /// <param name="a">Number to search for their coprime numbers</param>
        /// <returns>Table of coprime numbers to parameter a or returns null if parameter a has no coprime numbers</returns>
        public static BigInteger[] CoprimeNumbersTable(BigInteger a)// test, CoprimeNumbers
        {
            var foo = new List<BigInteger>();
            for (BigInteger i = 2; i < a; i++)
            {
                if (BigInteger.GreatestCommonDivisor(i, a) == 1)
                {
                    foo.Add(i);
                }
            }
            if (foo.Count == 0)
                return null;
            else
                return foo.ToArray();
        }

        /// <summary>
        /// Returns random coprime number to 'a'
        /// </summary>
        /// <param name="a">Number to search for their coprime numbers</param>
        /// <returns></returns>
        public static BigInteger ReturnCoprimeNumber(BigInteger a)// test, CoprimeNumbers
        {
            var foo = new List<BigInteger>();
            for (var i = BigInteger.ModPow(RandomBigInteger(1, 100), RandomBigInteger(1, 100), a); i < a; i++)
            {
                if (BigInteger.GreatestCommonDivisor(i, a) == 1)
                {
                    return i;
                }
            }
            return 0;
        }

        /// <summary>
        /// Returns true modulus, not a remainder
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static BigInteger Modulus(BigInteger a, BigInteger b)
        {
            return (a % b + b) % b;
        }

        public static string BinaryRepresentation(BigInteger number, int numberOfBitsRepresenting = 0)
        {
            var num = number;
            var rep = new StringBuilder();
            BigInteger reminder;

            while (true)
            {
                num = BigInteger.DivRem(num, 2, out reminder);
                rep.Append(reminder);
                if (num == 0)
                {
                    break;
                }
            }

            while (rep.Length < numberOfBitsRepresenting)
            {
                rep.Append(0);
            }

            var foo = rep.ToString();
            var bar = foo.ToCharArray();
            Array.Reverse(bar);
            return new string(bar);
        }
    }

    public static class MyExtensions
    {
        public static string PrintArray(this short[] arr)
        {
            var foo = new StringBuilder();

            foreach (var item in arr)
            {
                foo.Append(item + " ");
            }

            return foo.ToString();
        }
    }
}