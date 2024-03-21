using Crypto;
using Crypto.Dto;
using Crypto.Helpers;
using System.Net.Sockets;
using System.Text;
using static Crypto.KeyExchange;

namespace Server
{
    public class Session(TcpClient tcpClient)
    {
        private readonly TcpClient _tcpClient = tcpClient ?? throw new ArgumentNullException();

        private StreamReader _reader;
        private StreamWriter _writer;

        public Func<string>? GetSecretDataHandler { get; set; }

        public async Task ProcessConnectionAsync()
        {
            if (GetSecretDataHandler is null)
            {
                throw new ArgumentNullException(nameof(GetSecretDataHandler));
            }

            var secretMessage = GetSecretDataHandler.Invoke();

            try
            {
                using NetworkStream stream = _tcpClient.GetStream();
                _reader = new StreamReader(stream);
                _writer = new StreamWriter(stream);

                // step 2 - send PreMasterServerKey and initial curve param to client
                // handshake
                var keyPair = await SendPreMasterKeyAsync();

                // step 4
                // handshake - receive PreMasterClientKey and generate secret key
                var key = await GenerateSecretKey(keyPair);
                // record - encrypt and send message
                await EncryptMessage(key, secretMessage);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                _reader?.Close();
                _writer?.Close();
                _tcpClient?.Close();
            }
        }

        private async Task<IKeyPair> SendPreMasterKeyAsync()
        {
            // get PreMasterServerKey and initial curve param
            var preMasterInfo = new KeyExchangeDto();
            preMasterInfo.CurveName = "secp256k1";

            var serverKeyExchange = new KeyExchange(preMasterInfo.CurveName);
            var serverKeyPair = serverKeyExchange.GenerateKeyPair();
            var serverPub = serverKeyPair.GetSubjectPublicKeyInfo();

            preMasterInfo.PreMasterServerKey = serverPub;
            await _writer.SendDataAsync<KeyExchangeDto>(preMasterInfo);
            Console.WriteLine($"Sent PreMasterServerKey to client:\n {preMasterInfo.PreMasterServerKey}\n");

            return serverKeyPair;
        }

        private async Task<byte[]> GenerateSecretKey(IKeyPair serverKeyPair)
        {
            var preMasterInfo = await _reader.GetDataAsync<KeyExchangeDto>();
            Console.WriteLine($"Received PreMasterClientKey from client:\n {preMasterInfo.PreMasterClientKey}\n");
            var key = serverKeyPair.GenerateSecretKey(preMasterInfo.PreMasterClientKey);
            Console.WriteLine($"Generated secrete key on server side:\n {Convert.ToBase64String(key)}\n");
            return key;
        }

        private async Task EncryptMessage(byte[] key, string secretMessage)
        {
            byte[] plainText = Encoding.UTF8.GetBytes(secretMessage);
            var nonce = CryptoHelper.GenerateRandomBytes(size: 32);
            var cipherDto = Cipher.Encrypt(key, nonce, plainText);
            await _writer.SendDataAsync<CipherDto>(cipherDto);
            Console.WriteLine($"Sent EncryptedWithMACData to client:\n {cipherDto.EncryptedWithMACData}\n");
        }
    }
}
