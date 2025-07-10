using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    public class VulnerablePackagePath
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }
        [JsonPropertyName("isDevelopment")]
        public bool IsDevelopment { get; set; }
        [JsonPropertyName("isResolved")]
        public bool IsResolved { get; set; }
        [JsonPropertyName("name")]
        public string? Name { get; set; }
        [JsonPropertyName("version")]
        public string? Version { get; set; }
        [JsonPropertyName("vulnerabilityRiskLevel")]
        public string? VulnerabilityRiskLevel { get; set; }
    }

}
