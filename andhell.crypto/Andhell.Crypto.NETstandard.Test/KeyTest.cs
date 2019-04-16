using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace Andhell.Crypto.NETstandard.Test
{
    [TestClass]
    public class KeyTest
    {
        [TestMethod]
        public void DPAPIRoundTripCheck()
        {
            var key = new Key();
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                var storeable = key.Storable();
                var key2 = new Key(storeable);

                CollectionAssert.AreEqual(key.Bytes, key2.Bytes);
            }
            else
            {
                Assert.ThrowsException<NotImplementedException>(() => key.Storable());
            }
        }
    }
}
