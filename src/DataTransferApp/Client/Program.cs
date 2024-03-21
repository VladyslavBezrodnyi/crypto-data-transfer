using Crypto;
using Crypto.Dto;
using Crypto.Helpers;
using System.Net;
using System.Net.Sockets;

namespace Client
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var port = 8888;
            var localAddr = IPAddress.Loopback;
            var endpoint = new IPEndPoint(localAddr, port);

            using var client = new TcpClient();
            StreamReader? reader = null;
            StreamWriter? writer = null;
            try
            {
                // step 1 - start
                // handshake
                await client.ConnectAsync(endpoint);
                using NetworkStream stream = client.GetStream();

                reader = new StreamReader(stream);
                writer = new StreamWriter(stream);

                // step 3 - receive PreMasterServerKey and send PreMasterClientKey
                // handshake
                var key = await HandShakeAsync(reader, writer);

                // step 5 - decrypt
                // record
                var secretMessage = await GetMessageAsync(reader, key);

                Console.WriteLine($"Received decrypted message: {secretMessage}");

            }
            catch(Exception e)
            { 
                Console.WriteLine("could not connect...");
                Console.WriteLine(e.Message);
            }
            finally
            {
                reader?.Close();
                writer?.Close();
                client.Close();
            }
            Console.ReadKey();
        }

        private static async Task<byte[]> HandShakeAsync(StreamReader reader, StreamWriter writer)
        {
            // get PreMasterServerKey and initial curve param
            var preMasterInfo = await reader.GetDataAsync<KeyExchangeDto>();
            Console.WriteLine($"Received PreMasterServerKey from server:\n {preMasterInfo.PreMasterServerKey}\n");

            // generate PreMasterClientKey
            var clientKeyExchange = new KeyExchange(preMasterInfo.CurveName);
            var clientKeyPair = clientKeyExchange.GenerateKeyPair();
            var clientPub = clientKeyPair.GetSubjectPublicKeyInfo();

            // generate secrete key based on PreMasterServerKey
            var key = clientKeyPair.GenerateSecretKey(preMasterInfo.PreMasterServerKey);
            Console.WriteLine($"Generated secrete key on client side:\n {Convert.ToBase64String(key)}\n");

            // send PreMasterClientKey
            preMasterInfo.PreMasterClientKey = clientPub;
            await writer.SendDataAsync<KeyExchangeDto>(preMasterInfo);
            Console.WriteLine($"Sent PreMasterClientKey to server:\n {preMasterInfo.PreMasterClientKey}\n");

            return key;
        }

        private static async Task<string> GetMessageAsync(StreamReader reader, byte[] key)
        {
            var cipherDto = await reader.GetDataAsync<CipherDto>();
            Console.WriteLine($"Received EncryptedWithMACData from server:\n {cipherDto.EncryptedWithMACData}\n");
            var secretMessage = Cipher.Decrypt(key, cipherDto);
            return secretMessage;
        }
    }
}