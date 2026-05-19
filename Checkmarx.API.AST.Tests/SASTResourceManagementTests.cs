using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class SASTResourceManagementTests
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
        public void GetScansTest()
        {
            var result = astclient.SASTResourceManagement.GetScansAsync(limit: 10).Result;

            Assert.IsNotNull(result, "Scans collection should not be null.");
            Trace.WriteLine($"Total scans: {result.TotalCount}");

            if (result.Scans != null)
            {
                foreach (var scan in result.Scans)
                {
                    Trace.WriteLine($"Scan: {scan.Id}" +
                        $" | State: {scan.State}" +
                        $" | Queued: {scan.QueuedAt}" +
                        $" | Engine: {scan.Engine}");
                }
            }
        }

        [TestMethod]
        public void GetScansWithPaginationTest()
        {
            var result = astclient.SASTResourceManagement.GetScansAsync(offset: 0, limit: 5).Result;

            Assert.IsNotNull(result);
            Trace.WriteLine($"Total scans: {result.TotalCount}");
            Trace.WriteLine($"Returned: {result.Scans?.Count ?? 0} scans");
        }

        [TestMethod]
        public void GetScansWithDeletedTest()
        {
            var result = astclient.SASTResourceManagement.GetScansAsync(limit: 10, withDeleted: true).Result;

            Assert.IsNotNull(result);
            Trace.WriteLine($"Total scans (including deleted): {result.TotalCount}");

            if (result.Scans != null)
            {
                foreach (var scan in result.Scans)
                {
                    Trace.WriteLine($"Scan: {scan.Id} | State: {scan.State}");
                }
            }
        }

        [TestMethod]
        public void GetScansFilterByIdsTest()
        {
            var all = astclient.SASTResourceManagement.GetScansAsync(limit: 3).Result;

            if (all?.Scans == null || !all.Scans.Any())
            {
                Trace.WriteLine("No scans available to filter by IDs.");
                return;
            }

            var ids = all.Scans
                .Where(s => s.Id.HasValue)
                .Select(s => s.Id.Value)
                .ToList();

            var filtered = astclient.SASTResourceManagement.GetScansAsync(ids: ids).Result;

            Assert.IsNotNull(filtered);
            Trace.WriteLine($"Filtered by {ids.Count} IDs, returned: {filtered.Scans?.Count ?? 0}");

            if (filtered.Scans != null)
            {
                foreach (var scan in filtered.Scans)
                {
                    Trace.WriteLine($"  Scan: {scan.Id} | State: {scan.State}");
                }
            }
        }

        [TestMethod]
        public void GetScanByIdTest()
        {
            var all = astclient.SASTResourceManagement.GetScansAsync(limit: 1).Result;

            if (all?.Scans == null || !all.Scans.Any())
            {
                Trace.WriteLine("No scans available to retrieve by ID.");
                return;
            }

            var firstId = all.Scans.First().Id;
            if (!firstId.HasValue)
            {
                Trace.WriteLine("First scan has no ID.");
                return;
            }

            var scan = astclient.SASTResourceManagement.GetScanAsync(firstId.Value).Result;

            Assert.IsNotNull(scan, "Scan should not be null.");
            Assert.AreEqual(firstId, scan.Id);

            Trace.WriteLine($"Scan: {scan.Id}");
            Trace.WriteLine($"  State: {scan.State}");
            Trace.WriteLine($"  Queued at: {scan.QueuedAt}");
            Trace.WriteLine($"  Allocated at: {scan.AllocatedAt}");
            Trace.WriteLine($"  Running at: {scan.RunningAt}");
            Trace.WriteLine($"  Engine: {scan.Engine}");

            if (scan.Properties != null)
            {
                foreach (var prop in scan.Properties)
                {
                    Trace.WriteLine($"  Property: {prop.Key} = {prop.Value}");
                }
            }
        }
    }
}
