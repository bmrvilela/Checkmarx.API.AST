using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AIAssetsTests
    {
        public static IConfigurationRoot Configuration { get; private set; }

        private static ASTClient astclient;

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

            Configuration = builder.Build();

            if (!string.IsNullOrWhiteSpace(Configuration["API_KEY"]))
            {
                astclient = new ASTClient(
                    new System.Uri(Configuration["ASTServer"]),
                    new System.Uri(Configuration["AccessControlServer"]),
                    Configuration["Tenant"],
                    Configuration["API_KEY"]);
            }
            else
            {
                astclient = new ASTClient(
                    new System.Uri(Configuration["ASTServer"]),
                    new System.Uri(Configuration["AccessControlServer"]),
                    Configuration["Tenant"],
                    Configuration["ClientId"],
                    Configuration["ClientSecret"]);
            }
        }

        [TestMethod]
        public void GetFindingsTest()
        {
            var result = astclient.AIAssets.GetFindingsAsync(limit: 10).Result;

            Trace.WriteLine($"Total findings: {result.Total}");
            Trace.WriteLine($"Current page: {result.CurrentPage} / Last page: {result.LastPage}");

            if (result.Data != null)
            {
                foreach (var finding in result.Data)
                {
                    Trace.WriteLine($"Finding: {finding.Id}" +
                        $" | Asset: {finding.Asset?.AssetName}" +
                        $" | Provider: {finding.Asset?.Provider}" +
                        $" | Project: {finding.Project?.Name}");
                }
            }
        }

        [TestMethod]
        public void GetFindingsWithFiltersTest()
        {
            var result = astclient.AIAssets.GetFindingsAsync(
                limit: 5,
                offset: 0,
                orderColumn: AIAssets_OrderColumn.CreatedAt,
                orderDirection: AIAssets_OrderDirection.Desc,
                includeEvidences: true).Result;

            Trace.WriteLine($"Total findings: {result.Total}");

            if (result.Data != null)
            {
                foreach (var finding in result.Data)
                {
                    Trace.WriteLine($"Finding: {finding.Id}" +
                        $" | Asset: {finding.Asset?.AssetName}" +
                        $" | Type: {finding.Asset?.AssetType?.DisplayFormat}");
                }
            }
        }

        [TestMethod]
        public void GetFindingByIdTest()
        {
            var findings = astclient.AIAssets.GetFindingsAsync(limit: 1).Result;

            if (findings.Data == null || !findings.Data.Any())
            {
                Trace.WriteLine("No findings available to test GetFindingByID.");
                return;
            }

            var firstFinding = findings.Data.First();
            Assert.IsNotNull(firstFinding.Id, "Finding ID should not be null.");

            var detail = astclient.AIAssets.GetFindingByIDAsync(firstFinding.Id.Value).Result;

            Assert.IsNotNull(detail, "Finding detail should not be null.");
            Assert.AreEqual(firstFinding.Id, detail.Id);

            Trace.WriteLine($"Finding: {detail.Id}");
            Trace.WriteLine($"  Asset: {detail.Asset?.AssetName} ({detail.Asset?.Provider})");
            Trace.WriteLine($"  Project: {detail.Project?.Name}");

            if (detail.Evidences != null)
            {
                Trace.WriteLine($"  Evidences: {detail.Evidences.Count}");
                foreach (var evidence in detail.Evidences)
                {
                    Trace.WriteLine($"    [{evidence.EvidenceType}] {evidence.EvidencePath}" +
                        $" lines {evidence.EvidenceLineStart}-{evidence.EvidenceLineEnd}");
                }
            }
        }

        [TestMethod]
        public void GetAssetTypesTest()
        {
            var assetTypes = astclient.AIAssets.GetAssetTypesAsync().Result;

            Assert.IsNotNull(assetTypes, "Asset types collection should not be null.");

            foreach (var assetType in assetTypes)
            {
                Trace.WriteLine($"Asset Type: {assetType.Id}" +
                    $" | Display: {assetType.DisplayFormat}" +
                    $" | Match: {assetType.MatchFormat}");
            }
        }

        [TestMethod]
        public void GetAssetsTest()
        {
            var result = astclient.AIAssets.GetAssetsAsync().Result;

            Trace.WriteLine($"Total assets: {result.Total}");
            Trace.WriteLine($"Current page: {result.CurrentPage} / Last page: {result.LastPage}");

            if (result.Data != null)
            {
                foreach (var asset in result.Data)
                {
                    Trace.WriteLine($"Asset: {asset.Id}" +
                        $" | Name: {asset.AssetName}" +
                        $" | Provider: {asset.Provider}" +
                        $" | License: {asset.License}" +
                        $" | Type: {asset.AssetType?.DisplayFormat}");
                }
            }
        }

        [TestMethod]
        public void GetApplicationsTest()
        {
            var result = astclient.AIAssets.GetApplicationsAsync(limit: 10).Result;

            Trace.WriteLine($"Total applications: {result.Total}");
            Trace.WriteLine($"Current page: {result.CurrentPage} / Last page: {result.LastPage}");

            if (result.Data != null)
            {
                foreach (var app in result.Data)
                {
                    Trace.WriteLine($"Application: {app.Id}" +
                        $" | Name: {app.Name}" +
                        $" | Tenant: {app.TenantId}");
                }
            }
        }

        [TestMethod]
        public void AggregateFindingsByAssetTypeTest()
        {
            var result = astclient.AIAssets.AggregateFindingGroupsAsync(AIAssets_GroupBy.AssetType).Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.GroupsCounter != null)
            {
                foreach (var group in result.GroupsCounter)
                {
                    Trace.WriteLine($"Asset Type: {group.AssetTypeName} ({group.AssetType})" +
                        $" | Count: {group.Count}");
                }
            }
        }

        [TestMethod]
        public void AggregateFindingsByProjectTest()
        {
            var result = astclient.AIAssets.AggregateFindingGroupsAsync(AIAssets_GroupBy.ProjectName).Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.GroupsCounter != null)
            {
                foreach (var group in result.GroupsCounter)
                {
                    Trace.WriteLine($"Project: {group.ProjectName} ({group.ProjectId})" +
                        $" | Count: {group.Count}");
                }
            }
        }

        [TestMethod]
        public void AggregateFindingsByApplicationTest()
        {
            var result = astclient.AIAssets.AggregateFindingGroupsAsync(AIAssets_GroupBy.ApplicationName).Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.GroupsCounter != null)
            {
                foreach (var group in result.GroupsCounter)
                {
                    Trace.WriteLine($"Application: {group.ApplicationName} ({group.ApplicationId})" +
                        $" | Count: {group.Count}");
                }
            }
        }
    }
}
