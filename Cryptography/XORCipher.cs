using System;

namespace Cryptography
{
    public class XORCipher : ICipher
    {
        private ushort _key;

        public ushort Key
        {
            get { return _key; }
        }

        public XORCipher(ushort key)
        {
            if (key == 0)
            {
                throw new ArgumentException("Key cannot be 0");
            }
            _key = key;
        }

        public XORCipher()
        {
            _key = (ushort)Cryptography.RandomBigInteger(1, 100);
        }

        public override string ToString()
        {
            return "(" + _key.ToString() + ")";
        }

        public string Encrypt(string plainText)
        {
            var codedText = Cryptography.CodeText(plainText);

            for (int i = 0; i < plainText.Length; i++)
            {
                codedText[i] = (short)(codedText[i] ^ _key);
            }
            return String.Join<short>(" ", codedText);
        }

        public string Decrypt(string cipherText)
        {
            var encryptedTable = Array.ConvertAll<string, short>(cipherText.Split(' '), x => Int16.Parse(x));

            for (int i = 0; i < encryptedTable.Length; i++)
            {
                encryptedTable[i] = (short)(encryptedTable[i] ^ _key);
            }
            return Cryptography.DecodeText(encryptedTable);
        }
    }
}