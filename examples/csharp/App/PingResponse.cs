using Newtonsoft.Json;

namespace App
{
    public class PingResponse
    {
        [JsonProperty("message")]
        public string Message { get; set; }
    }
}