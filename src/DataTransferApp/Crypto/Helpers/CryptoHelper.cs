using Org.BouncyCastle.Security;

namespace Crypto.Helpers
{
    public static class CryptoHelper
    {
        public static byte[] GenerateRandomBytes(int size)
        {
            var randomGen = new SecureRandom();
            var randomBytes = new byte[size];
            randomGen.NextBytes(randomBytes);
            return randomBytes;

        }
    }
}
