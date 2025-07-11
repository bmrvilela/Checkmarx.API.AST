using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    public class PackageInfo
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }
        [JsonPropertyName("packageRepository")]
        public string? PackageRepository { get; set; }
        [JsonPropertyName("version")]
        public string? Version { get; set; }
    }

}
