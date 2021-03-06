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
            if (!_aes.ValidKeySize(aesKeyBitSize))
                throw new ArgumentOutOfRangeException("aesKeyBitSize", "Invalid key size.");
            _aes.KeySize = aesKeyBitSize;
            _aes.BlockSize = blockSize;
            _aes.GenerateKey();
            _aes.GenerateIV();

            _rsa = new RSACryptoServiceProvider(rsaKeyBitSize);
        }

        public Encoding Encoding { get; set; } = Encoding.UTF32;

        public byte[] GetPublicRsaKey() => _rsa.ExportRSAPublicKey();

        public void SetPublicRsaKey(byte[] key) => _rsa.ImportRSAPublicKey(key, out int _);

        public CryptInfo GetInfo()
        {
            return new CryptInfo
            {
                EncryptedAesKey = RsaEncrypt(_aes.Key),
                EncryptedAesIV = RsaEncrypt(_aes.IV),
            };
        }

        public bool SetInfo(CryptInfo info)
        {
            try
            {
<<<<<<< HEAD
                _aes.Key = info.EncryptedAesKey;
                _aes.IV = info.EncryptedAesIV;
=======
                _aes.Key = RsaDecrypt(info.EncryptedAesKey);
                _aes.IV = RsaDecrypt(info.EncryptedAesIV);
>>>>>>> 671f7e1415490d77a132f3011653ccd38ac78311
            }
            catch(Exception ex) { return false; }
            return true;
        }

        public byte[] RsaEncryptString(string inputString) => RsaEncrypt(Encoding.GetBytes(inputString));

        public byte[] RsaEncrypt(byte[] inputBuffer) => _rsa.Encrypt(inputBuffer, RSAEncryptionPadding.OaepSHA1);

        public string RsaDecryptString(byte[] inputBuffer) => Encoding.GetString(RsaDecrypt(inputBuffer));

        public byte[] RsaDecrypt(byte[] inputBuffer) => _rsa.Decrypt(inputBuffer, RSAEncryptionPadding.OaepSHA1);

        public byte[] AesEncryptString(string inputString) => AesEncrypt(Encoding.GetBytes(inputString));

        public byte[] AesEncrypt(byte[] inputBuffer)
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
        
        public string AesDecryptString(byte[] inputBuffer) => Encoding.GetString(AesDecrypt(inputBuffer));

        public byte[] AesDecrypt(byte[] inputBuffer)
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
