using Crypto.Dto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace Crypto
{
    public static class Cipher
    {
        private const int _macSize = 128;

        public static CipherDto Encrypt(byte[] key, byte[] nonce, byte[] plainText)
        {
            var aeadBlockCipher = CreateGcmBlockCipher(key, nonce, true);

            var outputSize = aeadBlockCipher.GetOutputSize(plainText.Length);
            var cipherTextData = new byte[outputSize];
            int result = aeadBlockCipher.ProcessBytes(plainText, 0, plainText.Length, cipherTextData, 0);
            aeadBlockCipher.DoFinal(cipherTextData, result);

            return new CipherDto()
            {
                EncryptedWithMACData = Convert.ToBase64String(cipherTextData),
                Nonce = Convert.ToBase64String(nonce)
            };
        }

        public static string Decrypt(byte[] key, CipherDto encryptedData)
        {
            var nonce = Convert.FromBase64String(encryptedData.Nonce);
            var cipherText = Convert.FromBase64String(encryptedData.EncryptedWithMACData);

            var aeadBlockCipher = CreateGcmBlockCipher(key, nonce, false);

            var outputSize = aeadBlockCipher.GetOutputSize(cipherText.Length);
            var plainText = new byte[outputSize];
            var len = aeadBlockCipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
            aeadBlockCipher.DoFinal(plainText, len); // check MAC and decrypt

            return Encoding.UTF8.GetString(plainText);
        }

        private static GcmBlockCipher CreateGcmBlockCipher(
            byte[] key, 
            byte[] nonce,
            bool isEncryption)
        {
            var keyParam = new KeyParameter(key);
            var aeadBlockCipher = new GcmBlockCipher(new AesEngine());
            var aeadParams = new AeadParameters(keyParam, _macSize, nonce, null);

            aeadBlockCipher.Init(isEncryption, aeadParams);

            return aeadBlockCipher;
        }
    }
}
