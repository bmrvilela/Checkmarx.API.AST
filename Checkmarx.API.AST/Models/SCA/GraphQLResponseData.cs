using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    /// <summary>
    /// Represents the 'data' root object in the GraphQL response.
    /// </summary>
    public class GraphQLResponseData
    {
        [JsonPropertyName("searchPackageVulnerabilityStateAndScoreActions")]
        public SearchPackageVulnerabilityStateAndScoreActions SearchPackageVulnerabilityStateAndScoreActions { get; set; }
    }


}
