using System.Net;
using System.Net.Sockets;

namespace Server
{
    public class Host(IPEndPoint endPoint)
    {
        private TcpListener _tcpListener = new(endPoint);

        public async Task StartServer(Func<string> getMessageHandler)
        {
            try
            {
                _tcpListener.Start();
                Console.WriteLine("Waiting for a connection...");

                while (true)
                {
                    TcpClient tcpClient = await _tcpListener.AcceptTcpClientAsync();
                    var client = new Session(tcpClient);
                    client.GetSecretDataHandler = getMessageHandler;
                    await client.ProcessConnectionAsync();
                    //Task.Run(client.ProcessConnectionAsync);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                _tcpListener.Stop();
            }
        }
    }
}
