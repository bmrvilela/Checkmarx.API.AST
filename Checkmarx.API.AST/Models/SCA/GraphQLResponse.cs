using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    /// <summary>
    /// Represents the overall GraphQL response.
    /// </summary>
    public class GraphQLResponse
    {
        [JsonPropertyName("data")]
        public GraphQLResponseData Data { get; set; }
    }


}
