using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    public class Cvss2
    {
        [JsonPropertyName("attackComplexity")]
        public string? AttackComplexity { get; set; }
        [JsonPropertyName("attackVector")]
        public string? AttackVector { get; set; }
        [JsonPropertyName("authentication")]
        public string? Authentication { get; set; }
        [JsonPropertyName("availability")]
        public string? Availability { get; set; }
        [JsonPropertyName("availabilityRequirement")]
        public string? AvailabilityRequirement { get; set; }
        [JsonPropertyName("baseScore")]
        public string? BaseScore { get; set; } // Can be double, but string to match example "7.5"
        [JsonPropertyName("collateralDamagePotential")]
        public string? CollateralDamagePotential { get; set; }
        [JsonPropertyName("confidentiality")]
        public string? Confidentiality { get; set; }
        [JsonPropertyName("confidentialityRequirement")]
        public string? ConfidentialityRequirement { get; set; }
        [JsonPropertyName("exploitCodeMaturity")]
        public string? ExploitCodeMaturity { get; set; }
        [JsonPropertyName("integrityImpact")]
        public string? IntegrityImpact { get; set; }
        [JsonPropertyName("integrityRequirement")]
        public string? IntegrityRequirement { get; set; }
        [JsonPropertyName("remediationLevel")]
        public string? RemediationLevel { get; set; }
        [JsonPropertyName("reportConfidence")]
        public string? ReportConfidence { get; set; }
        [JsonPropertyName("targetDistribution")]
        public string? TargetDistribution { get; set; }
    }

}
