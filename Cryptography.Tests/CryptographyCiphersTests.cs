using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Numerics;
using Cryptography;

namespace Cryptography.Tests
{
    class CryptographyCiphersTests
    {
        [Test, TestCaseSource(typeof(CryptographyTestsData), "plainText")]
        public void AffineTest(string plainText)
        {
            var test = new AffineCipher(new AffineCipherKey());
            Assert.AreEqual(plainText, test.decrypt(test.encrypt(plainText)));
            test = new AffineCipher(new AffineCipherKey(23, 88));
            Assert.AreEqual(plainText, test.decrypt(test.encrypt(plainText)));
        }

        [Test, TestCaseSource(typeof(CryptographyTestsData), "plainText")]
        public void XORCipherTest(string plainText)
        {
            var cipher = new XORCipher((short)Cryptography._rand.Next(1, 100));
            Assert.AreEqual(plainText, cipher.decrypt(cipher.encrypt(plainText)));
            cipher = new XORCipher();
            Assert.AreEqual(plainText, cipher.decrypt(cipher.encrypt(plainText)));
        }

        [Test, TestCaseSource(typeof(CryptographyTestsData), "plainText")]
        public void RSACipherTest(string plainText)
        {
            var cipher = new RSA(new RSAKey(Cryptography.GenerateRandomPrimeNumber128b(), Cryptography.GenerateRandomPrimeNumber128b()));
            Assert.AreEqual(plainText, cipher.decrypt(cipher.encrypt(plainText)));
            cipher = new RSA(new RSAKey());
            Assert.AreEqual(plainText, cipher.decrypt(cipher.encrypt(plainText)));
        }

        [Test, ExpectedException(typeof(ArgumentException))]
        public void RSACipherException()
        {
            new RSA(new RSAKey(12, 7));
        }
    }
}
