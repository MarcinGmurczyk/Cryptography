using NUnit.Framework;
using System;

// ReSharper disable All

namespace Cryptography.Tests
{
    internal class CryptographyCiphersTests
    {
        [Test, TestCaseSource(typeof(CryptographyTestsData), "PlainText")]
        public void AffineTest(string plainText)
        {
            var cipher = new AffineCipher(new AffineCipherKey());
            Assert.AreEqual(plainText, cipher.Decrypt(cipher.Encrypt(plainText)));
            cipher = new AffineCipher(new AffineCipherKey(23, 87));
            Assert.AreEqual(plainText, cipher.Decrypt(cipher.Encrypt(plainText)));
        }

        [Test, TestCaseSource(typeof(CryptographyTestsData), "PlainText")]
        public void XORCipherTest(string plainText)
        {
            var cipher = new XORCipher((ushort)Cryptography.RandomBigInteger(1, 100));
            Assert.AreEqual(plainText, cipher.Decrypt(cipher.Encrypt(plainText)));
            cipher = new XORCipher();
            Assert.AreEqual(plainText, cipher.Decrypt(cipher.Encrypt(plainText)));
        }

        [Test, TestCaseSource(typeof(CryptographyTestsData), "PlainText")]
        public void RSACipherTest(string plainText)
        {
            var cipher = new RSA(new RSAKey(103841, 103687));
            Assert.AreEqual(plainText, cipher.Decrypt(cipher.Encrypt(plainText)));
            cipher = new RSA(new RSAKey());
            Assert.AreEqual(plainText, cipher.Decrypt(cipher.Encrypt(plainText)));
        }

        [Test, ExpectedException(typeof(ArgumentException))]
        public void RSACipherException()
        {
            new RSA(new RSAKey(128, 256));
        }

        [Test, ExpectedException(typeof(ArgumentException))]
        public void XORCipherException()
        {
            new XORCipher(0);
        }

        [Test, ExpectedException(typeof(ArgumentException))]
        public void AffineCipherException()
        {
            new AffineCipher(new AffineCipherKey(2, 256));
        }
    }
}