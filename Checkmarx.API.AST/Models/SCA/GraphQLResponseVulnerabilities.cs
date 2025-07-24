using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    /// <summary>
    /// Represents the overall GraphQL response for vulnerabilities.
    /// </summary>
    public class GraphQLResponseVulnerabilities
    {
        [JsonPropertyName("data")]
        public GraphQLResponseDataVulnerabilities? Data { get; set; }
    }


}
