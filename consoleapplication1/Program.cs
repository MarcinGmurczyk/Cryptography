using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace ConsoleApplication1
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Cryptography.Initialize(new Random());
            Console.ReadLine();
        }
    }
}