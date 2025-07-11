using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    public class CweInfo
    {
        [JsonPropertyName("title")]
        public string? Title { get; set; }
    }

}
