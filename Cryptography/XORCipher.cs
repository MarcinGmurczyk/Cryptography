using System;

namespace Cryptography
{
    public class XORCipher : ICipher
    {
        public ushort Key { get; private set; }

        public XORCipher(ushort key)
        {
            if (key == 0)
            {
                throw new ArgumentException("Key cannot be 0");
            }
            Key = key;
        }

        public XORCipher()
        {
            Key = (ushort)Cryptography.RandomBigInteger(1, 100);
        }

        public override string ToString()
        {
            return "(" + Key.ToString() + ")";
        }

        public string Encrypt(string plainText)
        {
            var codedText = Cryptography.CodeText(plainText);

            for (var i = 0; i < plainText.Length; i++)
            {
                codedText[i] = (short)(codedText[i] ^ Key);
            }
            return string.Join(" ", codedText);
        }

        public string Decrypt(string cipherText)
        {
            var encryptedTable = Array.ConvertAll(cipherText.Split(' '), short.Parse);

            for (var i = 0; i < encryptedTable.Length; i++)
            {
                encryptedTable[i] = (short)(encryptedTable[i] ^ Key);
            }
            return Cryptography.DecodeText(encryptedTable);
        }
    }
}