namespace Crypto.Dto
{
    public class KeyExchangeDto
    {
        public string CurveName { get; set; }
        public string PreMasterServerKey { get; set; }
        public string PreMasterClientKey { get; set; }
    }
}
