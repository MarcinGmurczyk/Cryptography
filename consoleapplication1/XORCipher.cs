using System;

namespace Crypto
{
    internal class XORCipher : Cryptography, ICipher
    {
        private short _key;

        public short Key
        {
            get { return _key; }
            set { _key = value; }
        }

        public XORCipher(short key)
        {
            _key = key;
        }

        public string encrypt(string plainText)
        {
            var bar = Cryptography.CodeText(plainText);

            for (int i = 0; i < plainText.Length; i++)
            {
                bar[i] = (short)(bar[i] ^ _key);
            }
            return String.Join<short>(" ", bar);
        }

        public string decrypt(string cipherText)
        {
            var foo = Array.ConvertAll<string, short>(cipherText.Split(' '), x => Int16.Parse(x));

            for (int i = 0; i < foo.Length; i++)
            {
                foo[i] = (short)(foo[i] ^ _key);
            }
            return Cryptography.DecodeText(foo);
        }
    }
}