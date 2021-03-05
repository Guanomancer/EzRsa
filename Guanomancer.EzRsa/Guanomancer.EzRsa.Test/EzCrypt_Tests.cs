using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace Guanomancer.EzRsa.Test
{
    [TestFixture]
    public class EzCrypt_Tests
    {
        [Test]
        public void Encrypt_CreatesOutputArray()
        {
            var crypt = new EzCrypt();
            var str = "This is a test.";

            var buffer = crypt.Encrypt(str);

            Assert.IsNotNull(buffer);
            Assert.AreNotEqual(0, buffer.Length);
        }

        [Test]
        public void Decrypt_RestoresEncryptedString()
        {
            var crypt = new EzCrypt();
            var str = "This is a test.";
            var buffer = crypt.Encrypt(str);

            var result = crypt.DecryptToString(buffer);

            Assert.IsNotNull(result);
            Assert.AreEqual(str, result);
        }
    }
}
