using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Andhell.Crypto.NETstandard.Hash
{
    /// <summary>
    /// Represents a General Hashing function.
    /// </summary>
    /// <example>
    /// <code>
    /// IHashBox hashBox = new HashBox();
    ///
    /// var result = hashBox.Compute(TEST_STRING);
    ///
    /// if(result.Verify(TEST_STRING));
    ///     // Hash matched!
    /// </code>
    /// </example>
    public class HashBox : IHashBox
    {
        /// <summary>
        /// The optional Key used for hashing
        /// </summary>
        public IKey Key { get; protected set; }

        /// <summary>
        /// HashBox for General Hashing
        /// 
        /// Primitive: SHA512 / HMAC-SHA512 for keyed hashing
        /// </summary>
        /// <param name="generateKey">(Optional) Create a new random Key that is used for Keyed Hashing</param>
        public HashBox(bool generateKey = false)
        {
            if (generateKey)
                Key = new Key();
        }

        /// <summary>
        /// HashBox for keyed Hashing
        /// 
        /// Primitive: SHA512 / HMAC-SHA512 for keyed hashing
        /// </summary>
        /// <param name="key">The Key for Keyed Hashing</param>
        /// <exception cref="ArgumentNullException"></exception>
        public HashBox(IKey key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>
        /// Hashes a Message
        /// 
        /// Primitive: SHA512 / HMAC-SHA512 for keyed hashing
        /// </summary>
        /// <param name="message">The Message</param>
        /// <returns>Returns the Hash in an IHashed container</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public virtual IHashed Compute(string message)
        {
            if (string.IsNullOrEmpty(message)) throw new ArgumentNullException(nameof(message));

            return Compute(Utils.Secure.Encode(message));
        }


        /// <summary>
        /// Hashes data
        /// 
        /// Primitive: SHA512 / HMAC-SHA512 for keyed hashing
        /// </summary>
        /// <param name="data">The data to be hashed.</param>
        /// <returns>Returns the Hash in an IHashed container</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public virtual IHashed Compute(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            else if (data.Length == 0) throw new ArgumentException($"{nameof(data)} can't be empty");

            if (Key == null)
                return ComputeHash(data);
            else
                return ComputeKeyedHash(data);
        }

        /// <summary>
        /// Hashes a stream
        /// 
        /// Primitive: SHA512 / HMAC-SHA512 for keyed hashing
        /// </summary>
        /// <param name="data">The stream to be hashed.</param>
        /// <returns>Returns the Hash in an IHashed container</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IHashed Compute(Stream data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            using (HashAlgorithm hash = SHA512.Create())
            {
                var result = hash.ComputeHash(data);
                hash.Clear();
                return new GenericHash(result);
            }
        }

        private IHashed ComputeHash(byte[] data)
        {
            using (HashAlgorithm hash = SHA512.Create())
            {
                var result = hash.ComputeHash(data);
                hash.Clear();
                return new GenericHash(result);
            }
        }

        // Use HMAC for keyed Hashing
        private IHashed ComputeKeyedHash(byte[] data) => new HMACHashBox(Key).Compute(data);

        public void Clear()
        {
            Key?.Clear();
        }

        ~HashBox() => Clear();

    }

    /// <summary>
    /// Represents a Generic Hash result
    /// </summary>
    public class GenericHash : IHashed
    {
        /// <summary>
        /// Hash as Byte[]
        /// </summary>
        public byte[] HashBytes
        {
            get; protected set;
        }

        /// <summary>
        /// Hash as String
        /// 
        /// Uses the default string encoding from Utils.Secure.KeyEncode
        /// </summary>
        public string Hash { get { return Utils.Secure.KeyEncode(HashBytes); } }

        /// <summary>
        /// Represents a Generic Hash
        /// </summary>
        /// <param name="hash">The hashed bytes</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public GenericHash(byte[] hash)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            else if (hash.Length == 0) throw new ArgumentException($"{nameof(hash)} can't be empty");

            HashBytes = hash;
        }

        /// <summary>
        /// Represents a Generic Hash
        /// </summary>
        /// <param name="hash">Hash as String. Uses the default string encoding from Utils.Secure.KeyEncode</param>
        /// <exception cref="ArgumentNullException"></exception>
        public GenericHash(string hash)
        {
            HashBytes = string.IsNullOrEmpty(hash) ? throw new ArgumentNullException(nameof(hash)) : Utils.Secure.KeyEncode(hash);
        }

        /// <summary>
        /// Checks is the Hashes are equal
        /// </summary>
        /// <param name="hash">Hash to compare with</param>
        /// <returns>True, if the Hash are equal</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public virtual bool Verify(IHashed hash)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));

            return Utils.Secure.Compare(HashBytes, hash?.HashBytes);
        }

        /// <summary>
        /// Checks if the Hash of the plaintext equals the Hash
        /// </summary>
        /// <param name="plaintext">String to compare</param>
        /// <returns>True, if the Hash are equal</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public virtual bool Verify(string plaintext)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentNullException(nameof(plaintext));
            
            var hash = new HashBox().Compute(plaintext);
            return Verify(hash);
        }

        /// <summary>
        /// Checks if the Hash of the data equals the Hash
        /// </summary>
        /// <param name="plaindata">Bytes to compare</param>
        /// <returns>True, if the Hash are equal</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public virtual bool Verify(byte[] plaindata)
        {
            if (plaindata == null) throw new ArgumentNullException(nameof(plaindata));
            else if (plaindata.Length == 0) throw new ArgumentException($"{nameof(plaindata)} can't be empty");

            var hash = new HashBox().Compute(plaindata);
            return Verify(hash);
        }

        /// <summary>
        /// Checks if the Keyed Hash of the plaintext equals the hash
        /// </summary>
        /// <param name="plaintext">string to compare</param>
        /// <param name="key">Key used for hashing</param>
        /// <returns>true, is the hashed string matches the hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public virtual bool Verify(string plaintext, IKey key)
        {
            var hash = new HashBox(key).Compute(plaintext);
            return Verify(hash);
        }


        /// <summary>
        /// Checks if the Keyed Hash of the data equals the Hash
        /// </summary>
        /// <param name="plaindata">Bytes to compare</param>
        /// <param name="key">Key used for hashing</param>
        /// <returns>True, if the Hash are equal</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public virtual bool Verify(byte[] plaindata, IKey key)
        {
            var hash = new HashBox(key).Compute(plaindata);
            return Verify(hash);
        }
    }
}
