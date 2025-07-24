using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    /// <summary>
    /// Represents the 'data' root object in the GraphQL response for vulnerabilities.
    /// </summary>
    public class GraphQLResponseDataVulnerabilities
    {
        [JsonPropertyName("vulnerabilitiesRisksByScanId")]
        public VulnerabilitiesRisksByScanIdResult? VulnerabilitiesRisksByScanId { get; set; }
    }


}
