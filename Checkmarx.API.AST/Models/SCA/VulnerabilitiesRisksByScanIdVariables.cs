using System;
using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    /// <summary>
    /// Represents the variables for the 'vulnerabilitiesRisksByScanId' GraphQL query.
    /// </summary>
    public class VulnerabilitiesRisksByScanIdVariables
    {
        [JsonPropertyName("where")]
        public VulnerabilityModelFilterInput? Where { get; set; } // Nullable as per example

        [JsonPropertyName("take")]
        public int Take { get; set; }

        [JsonPropertyName("skip")]
        public int Skip { get; set; }

        [JsonPropertyName("order")]
        public VulnerabilitiesSort? Order { get; set; } // Nullable as per example, but has content

        [JsonPropertyName("scanId")]
        public Guid ScanId { get; set; }

        [JsonPropertyName("isExploitablePathEnabled")]
        public bool IsExploitablePathEnabled { get; set; }
    }


}
