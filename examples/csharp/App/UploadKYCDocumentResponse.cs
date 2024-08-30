using Newtonsoft.Json;

namespace App
{
    public class UploadKycDocumentResponse
    {
        [JsonProperty("kyc_document_id")]
        public string KycDocumentId { get; set; }
    }
}