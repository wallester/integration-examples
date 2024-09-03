using Newtonsoft.Json;

namespace App
{
    public class UploadKycDocumentRequest
    {
        [JsonProperty("kyc_check_id")]
        public string KycCheckId { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }
        
        [JsonIgnore]
        public byte[] FileContent { get; set; }
        
        [JsonIgnore]
        public string FileName { get; set; }
    }
}