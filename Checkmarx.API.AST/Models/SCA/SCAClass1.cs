using System.Net.Http;
using System.Net.Http.Json; // For ReadFromJsonAsync and JsonContent.Create
using System.Text.Json.Serialization; // For JsonPropertyName attribute
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Models.SCA
{

    // --- NEW: Request Models for VulnerabilitiesRisksByScanId ---

    /// <summary>
    /// Represents the 'where' filter input for VulnerabilityModel.
    /// This can be expanded to include more filter options as needed.
    /// </summary>
    public class VulnerabilityModelFilterInput
    {
        // Example: If you need to filter by 'severity' or other fields, add properties here.
        // [JsonPropertyName("severity")]
        // public string? Severity { get; set; }

        // Keeping it null as per the provided body, but allowing for future expansion.
    }

    /// <summary>
    /// Represents the 'order' input for sorting vulnerabilities.
    /// </summary>
    public class VulnerabilitiesSort
    {
        [JsonPropertyName("score")]
        public string? Score { get; set; } // e.g., "DESC", "ASC"
    }

    public class MethodMatch
    {
        [JsonPropertyName("fullName")]
        public string? FullName { get; set; }
        [JsonPropertyName("line")]
        public int Line { get; set; }
        [JsonPropertyName("namespace")]
        public string? Namespace { get; set; }
        [JsonPropertyName("shortName")]
        public string? ShortName { get; set; }
        [JsonPropertyName("sourceFile")]
        public string? SourceFile { get; set; }
    }

    public class MethodSourceCall
    {
        [JsonPropertyName("fullName")]
        public string? FullName { get; set; }
        [JsonPropertyName("line")]
        public int Line { get; set; }
        [JsonPropertyName("namespace")]
        public string? Namespace { get; set; }
        [JsonPropertyName("shortName")]
        public string? ShortName { get; set; }
        [JsonPropertyName("sourceFile")]
        public string? SourceFile { get; set; }
    }

    public class Reference
    {
        [JsonPropertyName("comment")]
        public string? Comment { get; set; }
        [JsonPropertyName("type")]
        public string? Type { get; set; }
        [JsonPropertyName("url")]
        public string? Url { get; set; }
    }


}
