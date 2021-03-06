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

            var buffer = crypt.AesEncryptString(str);

            Assert.IsNotNull(buffer);
            Assert.AreNotEqual(0, buffer.Length);
        }

        [Test]
        public void Decrypt_RestoresEncryptedString()
        {
            var crypt = new EzCrypt();
            var str = "This is a test.";
            var buffer = crypt.AesEncryptString(str);

            var result = crypt.AesDecryptString(buffer);

            Assert.IsNotNull(result);
            Assert.AreEqual(str, result);
        }

        [Test]
        public void SetPublicRsaKey_TransfereWorks()
        {
            var sender = new EzCrypt();
            var receiver = new EzCrypt();
            var str = "This is a test.";

            var key = sender.GetPublicRsaKey();
            receiver.SetPublicRsaKey(key);
            var info = receiver.GetInfo();
            var infoSet = sender.SetInfo(info);

            Assert.IsTrue(infoSet);

            var result = receiver.AesDecryptString(sender.AesEncryptString(str));

            Assert.AreEqual(str, result);
        }
    }
}
