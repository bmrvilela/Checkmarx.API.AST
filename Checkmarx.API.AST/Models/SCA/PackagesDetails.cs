using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Checkmarx.API.AST.Models.SCA
{
    public class PackagesDetails
    {
        [JsonPropertyName("data")]
        public PackagesDetailsData Data { get; set; }
    }

    public class PackagesDetailsData
    {
        [JsonPropertyName("packagesRows")]
        public PackagesRows PackagesRows { get; set; }
    }

    public class PackagesRows
    {
        [JsonPropertyName("items")]
        public List<PackageItem> Items { get; set; }

        [JsonPropertyName("totalCount")]
        public int TotalCount { get; set; }
    }

    public class PackageItem
    {
        [JsonPropertyName("dummyRiskyVersion")]
        public string DummyRiskyVersion { get; set; }

        [JsonPropertyName("isPotentialRiskyPackage")]
        public bool IsPotentialRiskyPackage { get; set; }

        [JsonPropertyName("pendingChanges")]
        public bool PendingChanges { get; set; }

        [JsonPropertyName("morEntityProfilesApplied")]
        public List<object> MorEntityProfilesApplied { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("pendingStatus")]
        public string PendingStatus { get; set; }

        [JsonPropertyName("statusValue")]
        public string StatusValue { get; set; }

        [JsonPropertyName("pendingStatusValue")]
        public string PendingStatusValue { get; set; }

        [JsonPropertyName("packageId")]
        public string PackageId { get; set; }

        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("version")]
        public string Version { get; set; }

        [JsonPropertyName("isViolatingPolicy")]
        public bool IsViolatingPolicy { get; set; }

        [JsonPropertyName("isMalicious")]
        public bool IsMalicious { get; set; }

        [JsonPropertyName("dependencyPathCount")]
        public int DependencyPathCount { get; set; }

        [JsonPropertyName("violatedPoliciesCount")]
        public int ViolatedPoliciesCount { get; set; }

        [JsonPropertyName("violatedPolicies")]
        public List<object> ViolatedPolicies { get; set; }

        [JsonPropertyName("relation")]
        public string Relation { get; set; }

        [JsonPropertyName("matchType")]
        public string MatchType { get; set; }

        [JsonPropertyName("legalRiskLevel")]
        public string LegalRiskLevel { get; set; }

        [JsonPropertyName("isDev")]
        public bool IsDev { get; set; }

        [JsonPropertyName("remediationTaskId")]
        public object RemediationTaskId { get; set; }

        [JsonPropertyName("isTest")]
        public bool IsTest { get; set; }

        [JsonPropertyName("isNpmVerified")]
        public bool IsNpmVerified { get; set; }

        [JsonPropertyName("isPluginDependency")]
        public bool IsPluginDependency { get; set; }

        [JsonPropertyName("isFramework")]
        public bool IsFramework { get; set; }

        [JsonPropertyName("packageRepository")]
        public string PackageRepository { get; set; }

        [JsonPropertyName("packageUsage")]
        public string PackageUsage { get; set; }

        [JsonPropertyName("releaseDate")]
        public DateTime ReleaseDate { get; set; }

        [JsonPropertyName("isPrivateDependency")]
        public object IsPrivateDependency { get; set; }

        [JsonPropertyName("isUnresolved")]
        public bool IsUnresolved { get; set; }

        [JsonPropertyName("cxScore")]
        public double? CxScore { get; set; }

        [JsonPropertyName("remediationAdvisory")]
        public RemediationAdvisory RemediationAdvisory { get; set; }

        [JsonPropertyName("outdatedModel")]
        public OutdatedModel OutdatedModel { get; set; }

        [JsonPropertyName("saasProviderInfo")]
        public object SaasProviderInfo { get; set; }

        [JsonPropertyName("effectiveLicenses")]
        public List<EffectiveLicense> EffectiveLicenses { get; set; }

        [JsonPropertyName("risks")]
        public Risks Risks { get; set; }

        [JsonPropertyName("suggestedFix")]
        public SuggestedFix SuggestedFix { get; set; }
    }

    public class EffectiveLicense
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("riskLevel")]
        public string RiskLevel { get; set; }
    }

    public class RemediationAdvisory
    {
        [JsonPropertyName("nextVersionWithoutVulnerabilities")]
        public object NextVersionWithoutVulnerabilities { get; set; }

        [JsonPropertyName("latestVersionWithoutVulnerabilities")]
        public object LatestVersionWithoutVulnerabilities { get; set; }
    }

    public class OutdatedModel
    {
        [JsonPropertyName("newestVersion")]
        public string NewestVersion { get; set; }

        [JsonPropertyName("versionsInBetween")]
        public int VersionsInBetween { get; set; }

        [JsonPropertyName("newestLibraryDate")]
        public DateTime? NewestLibraryDate { get; set; }
    }

    public class Risks
    {
        [JsonPropertyName("vulnerabilities")]
        public Vulnerabilities Vulnerabilities { get; set; }

        [JsonPropertyName("legalRisk")]
        public LegalRisk LegalRisk { get; set; }

        [JsonPropertyName("supplyChainRisks")]
        public SupplyChainRisks SupplyChainRisks { get; set; }

        [JsonPropertyName("vulnerabilitiesWithoutIgnored")]
        public VulnerabilitiesWithoutIgnored VulnerabilitiesWithoutIgnored { get; set; }

        [JsonPropertyName("supplyChainRisksWithoutIgnored")]
        public SupplyChainRisksWithoutIgnored SupplyChainRisksWithoutIgnored { get; set; }
    }

    public class SuggestedFix
    {
        [JsonPropertyName("type")]
        public string Type { get; set; }

        [JsonPropertyName("targetVersion")]
        public string TargetVersion { get; set; }

        [JsonPropertyName("vulnerabilityCounters")]
        public VulnerabilityCounters VulnerabilityCounters { get; set; }
    }

    public class Vulnerabilities
    {
        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        [JsonPropertyName("high")]
        public int High { get; set; }

        [JsonPropertyName("medium")]
        public int Medium { get; set; }

        [JsonPropertyName("low")]
        public int Low { get; set; }

        [JsonPropertyName("none")]
        public int None { get; set; }
    }

    public class VulnerabilitiesWithoutIgnored
    {
        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        [JsonPropertyName("high")]
        public int High { get; set; }

        [JsonPropertyName("medium")]
        public int Medium { get; set; }

        [JsonPropertyName("low")]
        public int Low { get; set; }

        [JsonPropertyName("none")]
        public int None { get; set; }
    }

    public class SupplyChainRisks
    {
        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        [JsonPropertyName("high")]
        public int High { get; set; }

        [JsonPropertyName("medium")]
        public int Medium { get; set; }

        [JsonPropertyName("low")]
        public int Low { get; set; }

        [JsonPropertyName("none")]
        public int None { get; set; }
    }

    public class SupplyChainRisksWithoutIgnored
    {
        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        [JsonPropertyName("high")]
        public int High { get; set; }

        [JsonPropertyName("medium")]
        public int Medium { get; set; }

        [JsonPropertyName("low")]
        public int Low { get; set; }

        [JsonPropertyName("none")]
        public int None { get; set; }
    }

    public class LegalRisk
    {
        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        [JsonPropertyName("high")]
        public int High { get; set; }

        [JsonPropertyName("medium")]
        public int Medium { get; set; }

        [JsonPropertyName("low")]
        public int Low { get; set; }

        [JsonPropertyName("none")]
        public int None { get; set; }
    }

    public class VulnerabilityCounters
    {
        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        [JsonPropertyName("high")]
        public int High { get; set; }

        [JsonPropertyName("medium")]
        public int Medium { get; set; }

        [JsonPropertyName("low")]
        public int Low { get; set; }
    }
}
