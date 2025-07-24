using System.Collections.Generic;
using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
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


}
