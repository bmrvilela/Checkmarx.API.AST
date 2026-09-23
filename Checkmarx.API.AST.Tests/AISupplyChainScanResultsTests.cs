using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AISupplyChainScanResultsTests
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
        public void GetProjectsScanResultsTest()
        {
            var projects = astclient.GetAllProjectsDetails();
            foreach (var project in projects)
            {
                var aiscScans = astclient.GetAISupplyChainScans(project.Id);
                if (aiscScans.Any())
                {
                    foreach (var scan in aiscScans)
                    {
                        try
                        {
                            var results = astclient.GetAISupplyChainScanResults(scan.Id);
                            if (results.Any())
                            {
                                Trace.WriteLine($"Project {project.Id} - Scan {scan.Id} - {results.Count()}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Trace.WriteLine($"ERROR Project {project.Id} - Scan {scan.Id}: {ex.Message}");
                        }
                    }
                }
            }
        }

        private static Services.Scans.Scan GetLatestScanWithAIResultsDetails()
        {
            // Retrieve a recent completed scan to use as test fixture.
            // Adjust the filter if needed (e.g. scan type that includes AI supply chain).
            var scans = astclient.Scans.GetListOfScansAsync(limit: 20).Result;
            var scan = scans?.Scans?.FirstOrDefault(s => s.Status == Services.Scans.Status.Completed);
            if (scan == null)
                Assert.Inconclusive("No completed scans found in the tenant.");
            return scan;
        }

        private static Guid GetLatestScanWithAIResults()
        {
            return GetLatestScanWithAIResultsDetails().Id;
        }

        [TestMethod]
        public void GetScanResultsTest()
        {
            var scanId = GetLatestScanWithAIResults();

            var result = astclient.AISupplyChainScanResults.GetScanResultsAsync(scanId, limit: 10).Result;

            Trace.WriteLine($"Scan: {scanId}");
            Trace.WriteLine($"Total results: {result.Total}");
            Trace.WriteLine($"Current page: {result.CurrentPage} / Last page: {result.LastPage}");

            if (result.Data != null)
            {
                foreach (var item in result.Data)
                {
                    Trace.WriteLine($"Result: {item.EvidenceKey}" +
                        $" | Asset: {item.AssetName} ({item.AssetType})" +
                        $" | Provider: {item.Provider}" +
                        $" | Version: {item.Version}" +
                        $" | Status: {item.Status}" +
                        $" | Path: {item.Path}:{item.StartLine}");
                }
            }
        }

        [TestMethod]
        public void GetScanResultsWithFiltersTest()
        {
            var scanId = GetLatestScanWithAIResults();

            var result = astclient.AISupplyChainScanResults.GetScanResultsAsync(
                scanId,
                limit: 5,
                offset: 1,
                orderColumn: AISCSR_OrderColumn.AssetName,
                orderDirection: AISCSR_OrderDirection.Asc).Result;

            Trace.WriteLine($"Total results: {result.Total}");

            if (result.Data != null)
            {
                foreach (var item in result.Data)
                {
                    Trace.WriteLine($"Result: {item.EvidenceKey}" +
                        $" | Asset: {item.AssetName} ({item.AssetType})" +
                        $" | Provider: {item.Provider}" +
                        $" | Version: {item.Version}" +
                        $" | Status: {item.Status}");
                }
            }
        }

        [TestMethod]
        public void GetScanResultsFilterByStatusTest()
        {
            var scan = GetLatestScanWithAIResultsDetails();

            // The triage status filters only work when a projectId is supplied, since that is what
            // triggers the triage enrichment on the server side.
            var result = astclient.AISupplyChainScanResults.GetScanResultsAsync(
                scan.Id,
                evidenceStatus: AISCSR_Status.Monitored,
                projectId: scan.ProjectId,
                limit: 10).Result;

            Trace.WriteLine($"Monitored results: {result.Total}");

            if (result.Data != null)
            {
                foreach (var item in result.Data)
                {
                    Assert.AreEqual(AISCSR_Status.Monitored, item.Status, "All returned results should be Monitored.");
                    Trace.WriteLine($"  {item.AssetName} | {item.Provider} | {item.Version}");
                }
            }
        }

        [TestMethod]
        public void GetScanResultsWithTriageAndRisksTest()
        {
            var scan = GetLatestScanWithAIResultsDetails();

            var result = astclient.AISupplyChainScanResults.GetScanResultsAsync(
                scan.Id,
                projectId: scan.ProjectId,
                limit: 10).Result;

            Trace.WriteLine($"Total results: {result.Total}");

            if (result.Data != null)
            {
                foreach (var item in result.Data)
                {
                    var severities = item.RiskSummary?.RiskCountBySeverity == null
                        ? "-"
                        : string.Join(", ", item.RiskSummary.RiskCountBySeverity.Select(x => $"{x.Key}={x.Value}"));

                    Trace.WriteLine($"  {item.AssetName} ({item.AssetId})" +
                        $" | Risks: {item.RiskSummary?.TotalRisks} [{severities}]" +
                        $" | Evidence triage: {item.Triage?.Evidence?.Status}" +
                        $" | Asset triage: {item.Triage?.Asset?.Status}");
                }
            }
        }

        [TestMethod]
        public void GetScanResultsOrderByFirstDetectionTest()
        {
            var scanId = GetLatestScanWithAIResults();

            var result = astclient.AISupplyChainScanResults.GetScanResultsAsync(
                scanId,
                limit: 10,
                orderColumn: AISCSR_OrderColumn.AssetFirstDetectionDate,
                orderDirection: AISCSR_OrderDirection.Desc).Result;

            Trace.WriteLine($"Total results: {result.Total}");

            if (result.Data != null)
            {
                foreach (var item in result.Data)
                {
                    Trace.WriteLine($"  {item.AssetName} | Detected: {item.AssetFirstDetectionDate:yyyy-MM-dd HH:mm}");
                }
            }
        }

        [TestMethod]
        public void AggregateByAssetTypeTest()
        {
            var scanId = GetLatestScanWithAIResults();

            var result = astclient.AISupplyChainScanResults.GetAggregateScanResultsGroupsAsync(
                scanId,
                groupBy: "assetType").Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.ScanGroupsCounter != null)
            {
                foreach (var group in result.ScanGroupsCounter)
                {
                    Trace.WriteLine($"Asset Type: {group.AssetType}" +
                        $" | Count: {group.Count}");
                }
            }
        }

        [TestMethod]
        public void AggregateByProviderTest()
        {
            var scanId = GetLatestScanWithAIResults();

            var result = astclient.AISupplyChainScanResults.GetAggregateScanResultsGroupsAsync(
                scanId,
                groupBy: "provider").Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.ScanGroupsCounter != null)
            {
                foreach (var group in result.ScanGroupsCounter)
                {
                    Trace.WriteLine($"Provider: {group.Provider}" +
                        $" | Count: {group.Count}");
                }
            }
        }

        [TestMethod]
        public void AggregateByAssetNameTest()
        {
            var scanId = GetLatestScanWithAIResults();

            var result = astclient.AISupplyChainScanResults.GetAggregateScanResultsGroupsAsync(
                scanId,
                groupBy: "assetName").Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.ScanGroupsCounter != null)
            {
                foreach (var group in result.ScanGroupsCounter)
                {
                    Trace.WriteLine($"Asset: {group.AssetName}" +
                        $" | Provider: {group.Provider}" +
                        $" | Count: {group.Count}");
                }
            }
        }

        [TestMethod]
        public void AggregateByAssetTypeAndProviderTest()
        {
            var scanId = GetLatestScanWithAIResults();

            var result = astclient.AISupplyChainScanResults.GetAggregateScanResultsGroupsAsync(
                scanId,
                groupBy: "assetType,provider").Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.ScanGroupsCounter != null)
            {
                foreach (var group in result.ScanGroupsCounter)
                {
                    Trace.WriteLine($"Asset Type: {group.AssetType}" +
                        $" | Provider: {group.Provider}" +
                        $" | Count: {group.Count}");
                }
            }
        }

        [TestMethod]
        public void AggregateByAllFieldsTest()
        {
            var scanId = GetLatestScanWithAIResults();

            var result = astclient.AISupplyChainScanResults.GetAggregateScanResultsGroupsAsync(
                scanId,
                groupBy: "assetType,assetName,provider").Result;

            Assert.IsNotNull(result, "Aggregation result should not be null.");

            if (result.ScanGroupsCounter != null)
            {
                Trace.WriteLine($"Groups returned: {result.ScanGroupsCounter.Count}");
                foreach (var group in result.ScanGroupsCounter)
                {
                    Trace.WriteLine($"  [{group.AssetType}] {group.AssetName}" +
                        $" | Provider: {group.Provider}" +
                        $" | Version: {group.Version}" +
                        $" | Status: {group.Status}" +
                        $" | Count: {group.Count}");
                }
            }
        }
    }
}
