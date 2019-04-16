using Andhell.Crypto.Utils;
using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Andhell.Crypto.NETstandard.Symmetric
{
    class SecretKeyBox_AES
    {
        // Default Padding mode
        private const PaddingMode PADDING_MODE = PaddingMode.PKCS7;

        public static byte[] Create(byte[] data, IKey key, out Nonce nonce)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            else if (key == null) throw new ArgumentNullException(nameof(key));

            byte[] encrypted;

            using (var aes = Aes.Create())
            {
                aes.Padding = PADDING_MODE;
                aes.Key = key.Bytes;
                aes.GenerateIV();
                nonce = new Nonce(aes.IV);
                var cryptor = aes.CreateEncryptor();

                using (var memStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memStream, cryptor, CryptoStreamMode.Write))
                        cryptoStream.Write(data, 0, data.Length);

                    encrypted = memStream.ToArray();
                }
            }

            return encrypted;
        }

        public static byte[] Open(byte[] cipher, Nonce nonce, IKey key)
        {
            if (cipher == null) throw new ArgumentNullException(nameof(cipher));
            else if (key == null) throw new ArgumentNullException(nameof(key));
            else if (nonce == null) throw new ArgumentNullException(nameof(nonce));


            byte[] data;

            using (var aes = Aes.Create())
            {
                aes.Padding = PADDING_MODE;
                aes.Key = key.Bytes;
                aes.IV = nonce.Bytes;

                var cryptor = aes.CreateDecryptor();

                using (var memStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memStream, cryptor, CryptoStreamMode.Write))
                        cryptoStream.Write(cipher, 0, cipher.Length);
                    
                    data = memStream.ToArray();
                }

            }
            return data;
        }
    }
}
