using System;

namespace Andhell.Crypto.NETstandard
{
    /// <summary>
    /// Represents a unsecured password in plaintext
    /// </summary>
    /// <example>
    /// <code>
    /// var password = new Password("Correct Horse Battery Staple");
    /// 
    /// //use this to store in your Database
    /// ISecuredPassword storeablePassword = password.Storable();
    ///            
    /// //To Verify
    /// if (storeablePassword.Verify(password))
    /// {
    ///     Console.WriteLine("Password matched");
    /// }
    /// </code>
    /// </example>
    public class Password : IPassword
    {
        /// <summary>
        /// Password in plaintext
        /// </summary>
        public string Plaintext { get; private set; }

        private readonly int iterations = 500000;

        /// <summary>
        /// </summary>
        /// <param name="password"></param>
        public Password(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            Plaintext = password;
        }

        /// <summary>
        /// </summary>
        /// <param name="password"></param>
        /// <param name="iterations">Number of Iterations for PBKDF2</param>
        public Password(string password, int iterations)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));
            if (this.iterations <= 0)
                throw new ArgumentException("Number of iterations can't be negativ or null", nameof(iterations));

            Plaintext = password;
            this.iterations = iterations;
        }

        /// <summary>
        /// Converts the Password to a format that can be stored and verified.
        /// 
        /// Uses the PBKDF2 Hashing algorithm
        /// </summary>
        /// <returns>SecuredPassword representation of the Plaintext Passwords</returns>
        public ISecuredPassword Storable() => Hash();

        private SecuredPassword Hash()
        {
            var hasher = new Hash.PBKDF2(Plaintext, iterations);
            return new SecuredPassword(hasher.Hash());
        }

        public IKey DeriveKey()
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Represents a secured password hash that can be stored and verified
    /// </summary>
    public class SecuredPassword : ISecuredPassword
    {
        /// <summary>
        /// </summary>
        /// <param name="hash">String represenation of a PBKDF2 Hash</param>
        public SecuredPassword(string hash)
        {
            if (string.IsNullOrEmpty(hash)) throw new ArgumentNullException(nameof(hash));
            
            Hash = hash;
        }

        /// <summary>
        /// Secure Hash representation of a Password
        /// 
        /// Uses the PBKDF2 Hashing algorithm
        /// </summary>
        public string Hash { get; private set; }
        

        /// <summary>
        /// Compare a Password to the Secured Hash
        /// 
        /// Uses the PBKDF2 Hashing algorithm
        /// </summary>
        /// <param name="password">Password that should be compared to the Hash</param>
        /// <returns>True if the Password matches the Hash, false otherwise</returns>
        public bool Verify(IPassword password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));

            var b = Utils.Secure.Encode(Hash);
            var intertions = BitConverter.ToInt32(Utils.Secure.Encode(Hash), 0);

            var hasher = new Hash.PBKDF2(password.Plaintext, intertions);
            return hasher.Verify(Hash);
        }
    }
}
