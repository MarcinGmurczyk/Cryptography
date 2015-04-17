using System;

namespace Cryptography
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var a = new RSA(new RSAKey());
            Console.WriteLine(a.Key);
            Console.ReadLine();
        }
    }
}