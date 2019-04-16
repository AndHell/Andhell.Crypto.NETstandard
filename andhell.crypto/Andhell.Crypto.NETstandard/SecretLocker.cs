using Andhell.Crypto.NETstandard.Symmetric;
using Andhell.Crypto.Utils;
using System;
using System.Collections.Generic;
using System.Text;
namespace Andhell.Crypto.NETstandard
{    
    /// <summary>
    /// Locks (Encrypt) and Unlocks (Decrypt) Data
    /// </summary>
    public class SecretLocker : ISecretLocker
    {
        private readonly IKey key;

        /// <summary>
        /// Create a Locker
        /// </summary>
        /// <param name="key">Key used in this Locker</param>
        public SecretLocker(IKey key)
        {
            this.key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>
        /// Encrypts the Data
        /// 
        /// IMPORTANT: this method does NOT provide integrity. Tampered messages will be decrypted without throwing an exception
        /// 
        /// Uses AES in CBC mode with PKCS7 padding
        /// </summary>
        /// <param name="data">Data to be encrypted</param>
        public ILocked Lock(byte[] data)
        {
            if (data == null || data?.Length == 0) throw new ArgumentNullException(nameof(data));

            Nonce nonce;
            var locked = SecretKeyBox_AES.Create(data, key, out nonce);
            return new Locked(locked, nonce);
        }

        /// <summary>
        /// Encrypts the Data
        /// 
        /// IMPORTANT: this method does NOT provide integrity. Tampered messages will be decrypted without throwing an exception
        /// 
        /// Uses AES in CBC mode with PKCS7 padding
        /// </summary>
        /// <param name="str">Data to be encrypted</param>
        public ILocked Lock(string str)
        {
            if (string.IsNullOrEmpty(str)) throw new ArgumentNullException(nameof(str));

            return Lock(Secure.Encode(str));
        }


        /// <summary>
        /// Decrypts the Data into a string
        /// </summary>
        /// <param name="locked">locked Data to be decrypted</param>
        public byte[] UnlockBytes(ILocked locked) {
            
            if (locked == null) throw new ArgumentNullException(nameof(locked));

            return SecretKeyBox_AES.Open(locked.Ciphertext, locked.Nonce, key);
        }

        
        /// <summary>
        /// Decrypts the Data into a string
        /// </summary>
        /// <param name="locked">locked Data to be decrypted</param>
        public string UnlockString(ILocked locked)
        {
            var tmp = UnlockBytes(locked);
            return Secure.Encode(tmp);
        }
    }

    /// <summary>
    /// Represents Locked Data that are encrypted with the SecretLocker
    /// </summary>
    public class Locked : ILocked
    {
        /// <summary>
        /// Nonce/IV used for encryption
        /// </summary>
        public Nonce Nonce { get; private set; }

        /// <summary>
        /// Combines Nonce and Ciphertext into a single byte[]
        /// 
        /// [NonceSize][Nonce][Ciphertext]
        /// [4 bytes][N - bytes][X - bytes]
        /// </summary>
        public byte[] Combined
        {
            get
            {
                byte[] tmp = new byte[sizeof(int) + Nonce.Bytes.Length + Ciphertext.Length];
                BitConverter.GetBytes(Nonce.Bytes.Length).CopyTo(tmp, 0);
                Nonce.Bytes.CopyTo(tmp, sizeof(int));
                Ciphertext.CopyTo(tmp, sizeof(int)+Nonce.Bytes.Length);
                return tmp;
            }
        }

        /// <summary>
        /// Encrypted Cipher Text
        /// </summary>
        public byte[] Ciphertext { get; private set; }

        public Locked(byte[] locked, Nonce nonce)
        {
            if (locked == null) throw new ArgumentNullException(nameof(locked));
            else if (nonce == null) throw new ArgumentNullException(nameof(nonce));

            Ciphertext = locked;
            Nonce = nonce;
        }

        public Locked(byte[] combined)
        {
            if (combined == null) throw new ArgumentNullException(nameof(combined));

            int nonceSize = BitConverter.ToInt32(combined, 0);
            var nonce = new byte[nonceSize];
            Array.Copy(combined, sizeof(int), nonce, 0, nonceSize);
            Nonce = new Nonce(nonce);

            int bytes = combined.Length - (sizeof(int) + nonceSize);
            Ciphertext = new byte[bytes];
            Array.Copy(combined, sizeof(int) + nonceSize, Ciphertext, 0, bytes);
        }
    }
}

