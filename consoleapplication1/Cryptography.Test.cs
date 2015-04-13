﻿using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace ConsoleApplication1
{
    [TestFixture]
    public class TestCryptography
    {
        [TestFixtureSetUp]
        public void Initialize()
        {
            Cryptography.Initialize(new Random());
        }
        
        [Test]
        public void CompareDictionaries()
        { 
            foreach (var item in Cryptography.ShortToCharTable)
            {
                var temp = Cryptography.CharToShortTable[item.Value];
                Assert.IsTrue(temp == item.Key);
            }
            Assert.AreEqual(Cryptography.ShortToCharTable.Count, Cryptography.CharToShortTable.Count);
        }

        [Test]
        public void TestPrimalityFunction()
        {
            Assert.IsFalse(Cryptography.PrimalityTest(0));
            Assert.IsFalse(Cryptography.PrimalityTest(52));
            Assert.IsFalse(Cryptography.PrimalityTest(-11));

            Assert.IsTrue(Cryptography.PrimalityTest(3));
            Assert.IsTrue(Cryptography.PrimalityTest(53));
            Assert.IsTrue(Cryptography.PrimalityTest(9223372036854775783));
        }

        private const string a = @"
                Oddzielili cię, syneczku, od snów, co jak motyl drżą,
                haftowali ci, syneczku, smutne oczy rudą krwią,
                malowali krajobrazy w żółte ściegi pożóg
                wyszywali wisielcami drzew płynące morze.

                    Wyuczyli cię, syneczku, ziemi twej na pamięć,
                    gdyś jej ścieżki powycinał żelaznymi łzami.
                    Odchowali cię w ciemności, odkarmili bochnem trwóg,
                    przemierzyłeś po omacku najwstydliwsze z ludzkich dróg.

                I wyszedłeś jasny synku, z czarną bronią w noc,
                i poczułeś, jak się jeży w dźwięku minut - zło.
                Zanim padłeś, jeszcze ziemię przeżegnałeś ręką.
                Czy to była kula, synku, czy to serce pękło?";

        [TestCase("aAąĄźŹćŃ")]
        [TestCase(@"
            ")]
        [TestCase(a)]
        [TestCase(@"!@#$%^&*()_+}{|:"":?><><||\\,./\;'][]-=90-8767435324123```~~~~~/*-/+9")]
        public void CodeDecodeText(string text)
        {
            Assert.AreEqual(text, Cryptography.DecodeText(Cryptography.CodeText(text)));
        }
        
        [Test]
        public void CoprimeNumbers()
        {
            var coprimeTo124 = new List<BigInteger>();
            var foo124 = "3 5 7 9 11 13 15 17 19 21 23 25 27 29 33 35 37 39 41 43 45 47 49 51 53 55 57 59 61 63 65 67 69 71 73 75 77 79 81 83 85" +
                                       " 87 89 91 95 97 99 101 103 105 107 109 111 113 115 117 119 121 123";
            var table124 = foo124.Split(' ');
            coprimeTo124.AddRange(Array.ConvertAll<string, BigInteger>(table124, ele => BigInteger.Parse(ele)));
            var result124 = Cryptography.ReturnCoprimeNumbersTable(124);

            Assert.AreEqual(result124, coprimeTo124.ToArray());

            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            var coprimeTo294 = new List<BigInteger>();
            var foo294 = "5 11 13 17 19 23 25 29 31 37 41 43 47 53 55 59 61 65 67 71 73 79 83 85 89 95 97 101 103 107 109 113 115 121 125 127 131" +
                                " 137 139 143 145 149 151 155 157 163 167 169 173 179 181 185 187 191 193 197 199 205 209 211 215 221 223 227 229 233 235"+
                                " 239 241 247 251 253 257 263 265 269 271 275 277 281 283 289 293";
            var table294 = foo294.Split(' ');
            coprimeTo294.AddRange(Array.ConvertAll<string, BigInteger>(table294, ele => BigInteger.Parse(ele)));
            var result294 = Cryptography.ReturnCoprimeNumbersTable(294);

            Assert.AreEqual(result294, coprimeTo294.ToArray());
        }

        [Test]
        public void MultiplicativeInverse()
        {
            Assert.AreEqual(31, (int)Cryptography.ComputeMultiplicativeInverse(12767, 256));
            Assert.AreEqual(-1, (int)Cryptography.ComputeMultiplicativeInverse(12768, 256));
        }

        [TestCase("aAąĄźŹćŃ")]
        [TestCase(a)]
        [TestCase(@"
            ")]
        [TestCase(@"!@#$%^&*()_+}{|:"":?><><||\\,./\;'][]-=90-8767435324123```~~~~~/*-/+9")]
        public void AffineTest(string plainText)
        {
            var test = new AffineCipher();
            Assert.AreEqual(plainText, test.decrypt(test.encrypt(plainText)));
        }
    }
}