namespace Crypto.Dto
{
    public class CipherDto
    {
        public required string EncryptedWithMACData { get; set; }
        public required string Nonce { get; set; }
    }
}
