using System;
using System.Security.Cryptography;

namespace Andhell.Crypto.NETstandard.Hash
{
    // ToDo: Define Finale Hash Format
    // [4 bytes: interations][32 byte salt][20 byte hash]

    internal class PBKDF2
    {
        const int SALT_SIZE = Utils.Secure.SALT_LENGTH;       // 256 bits
        const int HASH_SIZE = 20;                             // 160 bits (SHA-1)
        int ITERATIONS = 500000;                              // -.-

        private string plaintext;

        public PBKDF2(string password, int iterations= 500000)
        {
            plaintext = password;
            ITERATIONS = iterations;
        }

        public string Hash() => Utils.Secure.KeyEncode(HashBytes());

        public byte[] HashBytes() => Hash(plaintext, GenerateSalt());

        public bool Verify(string hash)
        {
            if (string.IsNullOrEmpty(hash))
                throw new ArgumentNullException(nameof(hash));

            var hashBytes = Utils.Secure.KeyEncode(hash);
            if (hashBytes.Length != sizeof(int) +  SALT_SIZE + HASH_SIZE)
                return false;

            var salt = GetSaltFromHash(hashBytes);
            ITERATIONS = GetIterationsFromHash(hashBytes);

            var passwordHash = Hash(plaintext, salt);

            return Utils.Secure.Compare(passwordHash, hashBytes);
        }

        private byte[] GenerateSalt() => Utils.Random.Bytes(SALT_SIZE);

        private byte[] GetSaltFromHash(byte[] hash)
        {
            var salt = new byte[SALT_SIZE];
            Array.Copy(hash, sizeof(int), salt, 0, SALT_SIZE);
            return salt;
        }

        private int GetIterationsFromHash(byte[] hash)
        {
            return BitConverter.ToInt32(hash, 0);
        }

        private byte[] Hash(string plain, byte[] salt)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(plain, salt, ITERATIONS);

            var hash = pbkdf2.GetBytes(HASH_SIZE);
            byte[] result = new byte[HASH_SIZE + SALT_SIZE+ sizeof(int)];

            Array.Copy(BitConverter.GetBytes(ITERATIONS), result, sizeof(int));
            Array.Copy(salt, 0, result, sizeof(int), SALT_SIZE);
            Array.Copy(hash, 0, result, sizeof(int) + SALT_SIZE, HASH_SIZE);
            return result;
        }
    }
}
