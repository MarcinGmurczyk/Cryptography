namespace Crypto
{
    internal interface ICipher
    {
        string encrypt(string plainText);

        string decrypt(string CipherText);
    }
}