using Newtonsoft.Json;

namespace App
{
    public class PingRequest
    {
        [JsonProperty("message")]
        public string Message { get; set; }
    }
}