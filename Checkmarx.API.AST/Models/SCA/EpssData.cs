using System;
using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    // --- NEW: Response Models for VulnerabilitiesRisksByScanId ---

    public class EpssData
    {
        [JsonPropertyName("cve")]
        public string? Cve { get; set; }
        [JsonPropertyName("date")]
        public DateTimeOffset Date { get; set; }
        [JsonPropertyName("epss")]
        public double Epss { get; set; }
        [JsonPropertyName("percentile")]
        public double Percentile { get; set; }
    }

}
