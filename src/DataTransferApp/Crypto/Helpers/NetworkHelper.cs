using System.Text.Json;

namespace Crypto.Helpers
{
    public static class NetworkHelper
    {
        public static async Task<T> GetDataAsync<T>(this StreamReader reader)
        {
            string? stringData;
            do
            {
                stringData = await reader.ReadLineAsync();
            } while (stringData is null);

            return JsonSerializer.Deserialize<T>(stringData);
        }

        public static async Task SendDataAsync<T>(this StreamWriter writer, T data)
        {
            var jsonData = JsonSerializer.Serialize(data);
            await writer.WriteLineAsync(jsonData);
            await writer.FlushAsync();
        }
    }
}
