using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json; // For ReadFromJsonAsync and JsonContent.Create
using System.Text.Json.Serialization; // For JsonPropertyName attribute
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Models.SCA
{


    /// <summary>
    /// Represents the overall GraphQL request body.
    /// </summary>
    public class GraphQLRequest<TVariables>
    {
        [JsonPropertyName("query")]
        public string Query { get; set; } = "";

        [JsonPropertyName("variables")]
        public TVariables? Variables { get; set; }
    }

    /// <summary>
    /// Represents the 'data' root object in the GraphQL response.
    /// </summary>
    public class GraphQLResponseData
    {
        [JsonPropertyName("searchPackageVulnerabilityStateAndScoreActions")]
        public SearchPackageVulnerabilityStateAndScoreActions SearchPackageVulnerabilityStateAndScoreActions { get; set; }
    }

    /// <summary>
    /// Represents the overall GraphQL response.
    /// </summary>
    public class GraphQLResponse
    {
        [JsonPropertyName("data")]
        public GraphQLResponseData Data { get; set; }
    }

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

    public class Cvss4
    {
        // Properties for CVSS4 if available, null in example
        // [JsonPropertyName("attackComplexity")]
        // public string? AttackComplexity { get; set; }
    }

    /// <summary>
    /// Represents the 'vulnerabilitiesRisksByScanId' data.
    /// </summary>
    public class VulnerabilitiesRisksByScanIdResult
    {
        [JsonPropertyName("totalCount")]
        public int TotalCount { get; set; }

        [JsonPropertyName("items")]
        public List<ScaVulnerability>? Items { get; set; }
    }

    /// <summary>
    /// Represents the 'data' root object in the GraphQL response for vulnerabilities.
    /// </summary>
    public class GraphQLResponseDataVulnerabilities
    {
        [JsonPropertyName("vulnerabilitiesRisksByScanId")]
        public VulnerabilitiesRisksByScanIdResult? VulnerabilitiesRisksByScanId { get; set; }
    }

    /// <summary>
    /// Represents the overall GraphQL response for vulnerabilities.
    /// </summary>
    public class GraphQLResponseVulnerabilities
    {
        [JsonPropertyName("data")]
        public GraphQLResponseDataVulnerabilities? Data { get; set; }
    }


}
