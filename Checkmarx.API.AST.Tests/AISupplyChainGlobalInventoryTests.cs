using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AISupplyChainGlobalInventoryTests
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
        public void GetResultsTest()
        {
            var result = astclient.AISupplyChainGlobalInventory.GetResultsAsync(limit: 10).Result;

            Trace.WriteLine($"Total results: {result.Total}");
            Trace.WriteLine($"Current page: {result.CurrentPage} / Last page: {result.LastPage}");

            if (result.Data != null)
            {
                foreach (var item in result.Data)
                {
                    Trace.WriteLine($"Result: {item.Id}" +
                        $" | Asset: {item.Asset?.AssetName}" +
                        $" | Provider: {item.Asset?.Provider}" +
                        $" | Project: {item.Project?.Name}");
                }
            }
        }

        [TestMethod]
        public void GetResultsWithFiltersTest()
        {
            var result = astclient.AISupplyChainGlobalInventory.GetResultsAsync(
                limit: 5,
                offset: 0,
                orderColumn: AISCGI_OrderColumn.CreatedAt,
                orderDirection: AISCGI_OrderDirection.Desc,
                includeEvidences: true).Result;

            Trace.WriteLine($"Total results: {result.Total}");

            if (result.Data != null)
            {
                foreach (var item in result.Data)
                {
                    Trace.WriteLine($"Result: {item.Id}" +
                        $" | Asset: {item.Asset?.AssetName}" +
                        $" | Type: {item.Asset?.AssetType?.DisplayFormat}" +
                        $" | License: {item.Asset?.License}");
                }
            }
        }

        [TestMethod]
        public void GetResultByIdTest()
        {
            var page = astclient.AISupplyChainGlobalInventory.GetResultsAsync(limit: 1).Result;

            if (page.Data == null || !page.Data.Any())
            {
                Trace.WriteLine("No results available to test GetResultByID.");
                return;
            }

            var first = page.Data.First();
            Assert.IsNotNull(first.Id, "Result ID should not be null.");

            var detail = astclient.AISupplyChainGlobalInventory.GetResultByIDAsync(first.Id.Value).Result;

            Assert.IsNotNull(detail, "Result detail should not be null.");
            Assert.AreEqual(first.Id, detail.Id);

            Trace.WriteLine($"Result: {detail.Id}");
            Trace.WriteLine($"  Asset: {detail.Asset?.AssetName} ({detail.Asset?.Provider})");
            Trace.WriteLine($"  Project: {detail.Project?.Name} | Scan: {detail.Project?.ScanId}");

            if (detail.Evidences != null)
            {
                Trace.WriteLine($"  Evidences: {detail.Evidences.Count}");
                foreach (var evidence in detail.Evidences)
                {
                    Trace.WriteLine($"    [{evidence.EvidenceType}] {evidence.EvidencePath}" +
                        $" lines {evidence.EvidenceLineStart}-{evidence.EvidenceLineEnd}" +
                        $" cols {evidence.EvidenceColumnStart}-{evidence.EvidenceColumnEnd}");
                }
            }
        }

        [TestMethod]
        public void AggregateResultsByAssetTypeTest()
        {
            var result = astclient.AISupplyChainGlobalInventory.AggregateResultsGroupsAsync(AISCGI_GroupBy.AssetType).Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.GroupsCounter != null)
            {
                foreach (var group in result.GroupsCounter)
                {
                    Trace.WriteLine($"Asset Type: {group.AssetTypeName} ({group.AssetTypeId})" +
                        $" | Count: {group.Count}");
                }
            }
        }

        [TestMethod]
        public void AggregateResultsByProjectTest()
        {
            var result = astclient.AISupplyChainGlobalInventory.AggregateResultsGroupsAsync(AISCGI_GroupBy.ProjectName).Result;

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
        public void AggregateResultsByApplicationTest()
        {
            var result = astclient.AISupplyChainGlobalInventory.AggregateResultsGroupsAsync(AISCGI_GroupBy.ApplicationName).Result;

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

        [TestMethod]
        public void AggregateResultsByAssetNameTest()
        {
            var result = astclient.AISupplyChainGlobalInventory.AggregateResultsGroupsAsync(AISCGI_GroupBy.AssetName).Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.GroupsCounter != null)
            {
                foreach (var group in result.GroupsCounter)
                {
                    Trace.WriteLine($"Asset: {group.AssetName} ({group.AssetId})" +
                        $" | Provider: {group.Provider}" +
                        $" | Count: {group.Count}");
                }
            }
        }

        [TestMethod]
        public void AggregateResultsByProviderTest()
        {
            var result = astclient.AISupplyChainGlobalInventory.AggregateResultsGroupsAsync(AISCGI_GroupBy.Provider).Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.GroupsCounter != null)
            {
                foreach (var group in result.GroupsCounter)
                {
                    Trace.WriteLine($"Provider: {group.Provider}" +
                        $" | Count: {group.Count}");
                }
            }
        }
    }
}
