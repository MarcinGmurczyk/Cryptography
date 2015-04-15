using System;

namespace Crypto
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Cryptography.Initialize(new Random());
            var a = "dupa ąż|6^";
            Console.WriteLine(a);

            var b = new XORCipher(45);
            var c = b.encrypt(a);

            Console.WriteLine(c);
            Console.WriteLine(b.decrypt(c));



            Console.ReadLine();
        }
    }
}