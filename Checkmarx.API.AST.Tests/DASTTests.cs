using Checkmarx.API.AST.Models.SCA;
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
    public class DASTTests
    {
        public static IConfigurationRoot Configuration { get; private set; }
        private static ASTClient astclient;

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<DASTTests>();

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
            var enviroments = astclient.GetEnviroments();

            foreach (var env in enviroments)
            {
                var scans = astclient.GetDASTScans(env.EnvironmentId);
                foreach (var scan in scans)
                {
                    var resultsCount = 0;
                    if (scan.HasResults == true)
                    {
                        var results = astclient.GetDASTScanResults(scan.ScanId).ToList();
                        resultsCount = results.Count;
                    }

                    Trace.WriteLine($"Environment: {env.EnvironmentId}, Scan: {scan.ScanId} - Results: {resultsCount}");
                }
            }
        }
    }
}
