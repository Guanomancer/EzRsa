using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Guanomancer.EzRsa
{
    public class EzCrypt
    {
        private Aes _aes;
        private RSA _rsa;

        public EzCrypt(int rsaKeyBitSize = 1024, int aesKeyBitSize = 256, int blockSize = 128)
        {
            if (rsaKeyBitSize % 8 != 0)
                throw new ArgumentException("RSA bit Size must be divisible by 8.", "rsaKeyBitSize");
            if (aesKeyBitSize % 8 != 0)
                throw new ArgumentException("AES bit Size must be divisible by 8.", "aesKeyBitSize");

            _aes = Aes.Create();
            _aes.Mode = CipherMode.CBC;
            _aes.KeySize = aesKeyBitSize;
            _aes.BlockSize = blockSize;
            _aes.GenerateKey();
            _aes.GenerateIV();

            _rsa = new RSACryptoServiceProvider(rsaKeyBitSize);
        }

        public byte[] Encrypt(string inputString) => Encrypt(Encoding.UTF8.GetBytes(inputString));

        public byte[] Encrypt(byte[] inputBuffer)
        {
            using (var encryptor = _aes.CreateEncryptor())
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(inputBuffer, 0, inputBuffer.Length);
                    }
                    return ms.ToArray();
                }
            }
        }
        
        public string DecryptToString(byte[] inputBuffer) => Encoding.UTF8.GetString(Decrypt(inputBuffer));

        public byte[] Decrypt(byte[] inputBuffer)
        {
            using (var decryptor = _aes.CreateDecryptor())
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(inputBuffer, 0, inputBuffer.Length);
                    }
                    return ms.ToArray();
                }
            }
        }
    }
}
