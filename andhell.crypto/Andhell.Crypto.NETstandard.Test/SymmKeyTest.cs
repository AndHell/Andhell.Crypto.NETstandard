using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Andhell.Crypto.NETstandard.Test
{
    [TestClass]
    public class SymmKeyTest
    {
        private readonly byte[] testKey = new byte[] {   14, 140, 113, 168,  14,  68,  45,  36,
                                                         33, 124,  40,   6, 123, 249,  29, 143,
                                                        111,  96,  92,  20, 120,  82, 107, 167,
                                                        124,  85, 253, 225,  87, 134,  84,  99 };
        private readonly byte[] combined = new byte[] {  16,   0,   0,    0,            //IV Size
                                                        31, 170, 70, 5, 190, 231, 90, 75,
                                                        104, 136, 181, 238, 255, 158, 40, 170,  //IV
                                                        19, 52, 19, 116, 162, 84, 216, 119, 218, 238, 192, 67, 225, 34, 78, 62, 17, 43, 81, 112, 184, 21, 198, 107, 153, 221, 12, 50, 109, 244, 189, 180, 248, 58, 50, 168, 189, 145, 223, 79, 132, 161, 232, 96, 114, 64, 254, 174 };
        private readonly byte[] testNonce = new byte[] { 31, 170, 70, 5, 190, 231, 90, 75, 104, 136, 181, 238, 255, 158, 40, 170 };
        private readonly byte[] testCipher = new byte[] { 19, 52, 19, 116, 162, 84, 216, 119, 218, 238, 192, 67, 225, 34, 78, 62, 17, 43, 81, 112, 184, 21, 198, 107, 153, 221, 12, 50, 109, 244, 189, 180, 248, 58, 50, 168, 189, 145, 223, 79, 132, 161, 232, 96, 114, 64, 254, 174 };
        public const string TEST_STRING = "eine kuh macht muh, viele kühe machen mühe";
        public const string TEST_STRING_CHANGED = "eine kuh macht muh, viele kühe machen muehe";

        [TestMethod]
        public void LockString()
        {
            var key = new Key();

            var sl = new SecretLocker(key);

            var en = sl.Lock(TEST_STRING);
            
            var de = sl.UnlockString(en);
            Assert.AreEqual(TEST_STRING, de);
        }

        [TestMethod]
        public void UnlockString_combined()
        {
            var key = new Key(testKey);

            var sl = new SecretLocker(key);

            var en = new Locked(combined);
            
            var de = sl.UnlockString(en);
            Assert.AreEqual(TEST_STRING, de);
        }

        [TestMethod]
        public void UnlockString_CipherWithNonce()
        {
            var key = new Key(testKey);

            var sl = new SecretLocker(key);

            var en = new Locked(testCipher, new Utils.Nonce(testNonce));

            var de = sl.UnlockString(en);
            Assert.AreEqual(TEST_STRING, de);
        }

        [TestMethod]
        public void UnlockString_CipherWithWrongNonce()
        {
            var key = new Key(testKey);

            var sl = new SecretLocker(key);
            var en = new Locked(testCipher, new Utils.Nonce());

            var de = "";
            Assert.ThrowsException<CryptographicException>(() => de = sl.UnlockString(en));
            Assert.AreNotEqual(TEST_STRING, de);
        }

        [TestMethod]
        public void UnlockString_CipherWithWrongNonce_ToShort()
        {
            var key = new Key(testKey);

            var sl = new SecretLocker(key);
            var en = new Locked(testCipher, new Utils.Nonce(5));

            var de = "";
            Assert.ThrowsException<CryptographicException>(() => de = sl.UnlockString(en));
            Assert.AreNotEqual(TEST_STRING, de);
        }

        [TestMethod]
        public void UnlockString_TamperdChipherText()
        {
            var key = new Key(testKey);

            var sl = new SecretLocker(key);
            var en = new Locked(testCipher, new Utils.Nonce(testNonce));
            
            //tamper ciphertext
            for (int i = 0; i < 5; i++)
                en.Ciphertext[i] = 0;

            var de = "";
            Assert.ThrowsException<CryptographicException>(() => de = sl.UnlockString(en));
            Assert.AreNotEqual(TEST_STRING, de);
        }

        [TestMethod]
        public void UnlockString_WrongKey()
        {
            var sl = new SecretLocker(new Key());
            var en = new Locked(testCipher, new Utils.Nonce(testNonce));
            
            var de = "";
            Assert.ThrowsException<CryptographicException>(() => de = sl.UnlockString(en));
            Assert.AreNotEqual(TEST_STRING, de);
        }


        [TestMethod]
        public void NullParameter()
        {
            byte[] nullBytes = null;
            string nullString = null;

            Assert.ThrowsException<ArgumentNullException>(() => new SecretLocker(null));
            Assert.ThrowsException<ArgumentNullException>(() => new SecretLocker(new Key(testKey)).Lock(nullBytes));
            Assert.ThrowsException<ArgumentNullException>(() => new SecretLocker(new Key(testKey)).Lock(nullString));
            Assert.ThrowsException<ArgumentNullException>(() => new SecretLocker(new Key(testKey)).Lock(""));

            Assert.ThrowsException<ArgumentNullException>(() => new SecretLocker(new Key(testKey)).UnlockBytes(null));
            Assert.ThrowsException<ArgumentNullException>(() => new SecretLocker(new Key(testKey)).UnlockString(null));


            Assert.ThrowsException<ArgumentNullException>(() => new Locked(null));
            Assert.ThrowsException<ArgumentNullException>(() => new Locked(null, new Utils.Nonce(testNonce)));
            Assert.ThrowsException<ArgumentNullException>(() => new Locked(testCipher, null));
            Assert.ThrowsException<ArgumentNullException>(() => new Locked(null, null));

        }
    }
}
