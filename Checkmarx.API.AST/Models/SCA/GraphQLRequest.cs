using System.Text.Json.Serialization; // For JsonPropertyName attribute

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


}
