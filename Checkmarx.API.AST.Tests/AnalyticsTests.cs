using Checkmarx.API.AST.Services.Analytics;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AnalyticsTests
    {
        public static IConfigurationRoot Configuration { get; private set; }

        private static ASTClient astclient;

        private static Guid projectId = new Guid("440a6404-f79d-4e50-8407-64be5d6d299a");

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<AnalyticsTests>();

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
        public void AnalyticsTest()
        {
            var type = Services.Analytics.KpiType.VulnerabilitiesBySeverityTotal;
            var startDate = DateTime.UtcNow.AddMonths(-6);
            var endDate = DateTime.UtcNow;

            try
            {
                var result = astclient.GetAnalyticsReport(type, startDate, endDate);
                Trace.WriteLine($"LoC: {result.Loc}");
                Trace.WriteLine($"Total: {result.Total}");
                foreach (var data in result.Distribution)
                    Trace.WriteLine($"Label: {data.Label} | Density: {data.Density} | Percentage: {data.Percentage} | Results: {data.Results}");
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting analytics report: {ex.Message}");
            }
        }


    }
}
