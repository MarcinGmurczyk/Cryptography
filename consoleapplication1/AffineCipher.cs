using System.Numerics;
using System.Text;

namespace ConsoleApplication1
{
    internal class AffineCipher : Cryptography
    {
        private int _valueA;

        public int ValueA
        {
            get { return _valueA; }
            private set { _valueA = value; }
        }

        private int _valueB;

        public int ValueB
        {
            get { return _valueB; }
            private set { _valueB = value; }
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

        /// <summary>
        /// Creates AffineCipher instance with random parameters
        /// </summary>
        public AffineCipher()
        {
            _valueA = (short)Cryptography.ReturnCoprimeNumber(Cryptography.CharToShortTable.Count);
            _valueB = Cryptography._rand.Next(1, Cryptography.CharToShortTable.Count + 1);
        }

        /// <summary>
        /// Creates AffineCipher instance with given parameters. (ax + b) mod m
        /// </summary>
        /// <param name="valueA">Value a</param>
        /// <param name="valueB">Value b</param>
        public AffineCipher(int valueA, int valueB)
        {
            _valueA = valueA;
            _valueB = valueB;
        }
        public string encrypt(string plainText)
        {
            var mod = Cryptography.CharToShortTable.Count;
            var foo = Cryptography.CodeText(plainText);
            var temp = new BigInteger();

            for (int i = 0; i < plainText.Length; i++)
            {
                temp = BigInteger.Multiply(_valueA, foo[i]);
                temp = BigInteger.Add(temp, _valueB);
                foo[i] = (short)Modulus(temp, mod);
            }
            return Cryptography.DecodeText(foo);
        }

        public string decrypt(string cipherText)
        {
            var mod = Cryptography.CharToShortTable.Count;
            var multInverse = Cryptography.ComputeMultiplicativeInverse(_valueA, mod);
            var foo = Cryptography.CodeText(cipherText);
            BigInteger temp;

            for (int i = 0; i < cipherText.Length; i++)
            {
                temp = BigInteger.Multiply(multInverse, foo[i] - _valueB);
                foo[i] = (short)Modulus(temp, mod);
            }
            return Cryptography.DecodeText(foo);
        }

        public override string ToString()
        {
            return "a = " + _valueA + ", b = " + _valueB;
        }
    }
}