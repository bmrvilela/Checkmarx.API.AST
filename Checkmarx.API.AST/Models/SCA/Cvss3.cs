using System.Text.Json.Serialization; // For JsonPropertyName attribute

namespace Checkmarx.API.AST.Models.SCA
{
    public class Cvss3
    {
        [JsonPropertyName("attackComplexity")]
        public string? AttackComplexity { get; set; }
        [JsonPropertyName("attackVector")]
        public string? AttackVector { get; set; }
        [JsonPropertyName("availability")]
        public string? Availability { get; set; }
        [JsonPropertyName("availabilityRequirement")]
        public string? AvailabilityRequirement { get; set; }
        [JsonPropertyName("baseScore")]
        public string? BaseScore { get; set; } // Can be double, but string to match example "10"
        [JsonPropertyName("confidentiality")]
        public string? Confidentiality { get; set; }
        [JsonPropertyName("confidentialityRequirement")]
        public string? ConfidentialityRequirement { get; set; }
        [JsonPropertyName("exploitCodeMaturity")]
        public string? ExploitCodeMaturity { get; set; }
        [JsonPropertyName("integrity")]
        public string? Integrity { get; set; }
        [JsonPropertyName("integrityRequirement")]
        public string? IntegrityRequirement { get; set; }
        [JsonPropertyName("privilegesRequired")]
        public string? PrivilegesRequired { get; set; }
        [JsonPropertyName("remediationLevel")]
        public string? RemediationLevel { get; set; }
        [JsonPropertyName("reportConfidence")]
        public string? ReportConfidence { get; set; }
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
        [JsonPropertyName("userInteraction")]
        public string? UserInteraction { get; set; }
    }

}
