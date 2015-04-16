using System;

namespace Crypto
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Cryptography.Initialize(new Random());
            var a = new RSA(new RSAKey());
            Console.WriteLine(a.Key);
            Console.ReadLine();
        }
    }
}