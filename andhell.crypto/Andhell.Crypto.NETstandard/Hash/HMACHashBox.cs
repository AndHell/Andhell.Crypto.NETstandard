using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Andhell.Crypto.NETstandard.Hash
{
    /// <summary>
    /// HashBox for Keyed Hashing
    /// 
    /// Primitive: HMAC-SHA512
    /// </summary>   
    /// <example>
    /// <code>
    /// string Text = "Hallo Welt!";
    /// Key key = new Key();
    /// HMACHashBox hmac = new Hash.HMACHashBox(key);
    /// Hashed hash = hmac.Compute(Text);
    ///
    /// var signed = hash.Hash;
    ///
    /// //Verify
    /// Hashed hash = new Hashed(signed);
    ///
    /// if (hash.Verify(Text, key))
    ///     // Authentication OK!
    /// locker.Clear();
    /// </code>
    /// </example>
    class HMACHashBox : HashBox
    {
        /// <summary>
        /// HashBox for Keyed Hashing
        /// 
        /// Creates a new Key
        /// </summary>
        public HMACHashBox() : base(generateKey: true)
        {
        }

        /// <summary>
        /// HashBox for Keyed Hashing
        /// </summary>
        /// <param name="key">The Key</param>
        public HMACHashBox(IKey key) : base(key)
        {
        }

        /// <summary>
        /// Hashes a Message
        /// 
        /// Primitive : HMAC-SHA512
        /// </summary>
        /// <param name="message">The message to be hashed.</param>
        /// <returns>Returns the Hash in an IHashed container</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public override IHashed Compute(string data) 
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));

            return Compute(Utils.Secure.Encode(data));
        }


        /// <summary>
        /// Hashes data
        /// 
        /// Primitive : HMAC-SHA512
        /// </summary>
        /// <param name="data">The data to be hashed.</param>
        /// <returns>Returns the Hash in an IHashed container</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public override IHashed Compute(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            else if (data.Length == 0) throw new ArgumentException($"{nameof(data)} can't be empty");
            
            return Compute(data, Key);
        }

        private HashedTag Compute(byte[] data, IKey key)
        {
            using (HMACSHA512 hmac = new HMACSHA512(Key.Bytes))
            {
                var hash = hmac.ComputeHash(data);
                hmac.Clear();
                return new HashedTag(hash);
            }
        }
    }

    /// <summary>
    /// Representes a HMAC tag
    /// </summary>
    public class HashedTag : GenericHash
    {

        public HashedTag(byte[] hash) : base(hash) { }

        public HashedTag(string hash) : base(hash) { }

        /// <summary>
        /// NOT DEFINED
        /// To compare a HashTag you always need a key
        /// </summary>
        public override bool Verify(string plaintext) => throw new NotImplementedException();

        /// <summary>
        /// NOT DEFINED
        /// To compare a HashTag you always need a key
        /// </summary>
        public override bool Verify(byte[] plaindata) => throw new NotImplementedException();
        
    }
}
