using System.Net;

namespace Server
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var port = 8888;
            var localAddr = IPAddress.Loopback; 
            var endPoint = new IPEndPoint(localAddr, port);
            var host = new Host(endPoint);
            await host.StartServer(() =>
            {
                // secrete message from server
                Console.WriteLine("Enter secret message:");
                return Console.ReadLine() ?? string.Empty;
            });
        }
    }
}