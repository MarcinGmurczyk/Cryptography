namespace Cryptography
{
    public interface ICipher
    {
        string encrypt(string plainText);

        string decrypt(string cipherText);
    }
}