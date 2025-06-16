using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
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
    public class SCATests
    {
        public static IConfigurationRoot Configuration { get; private set; }

        private static ASTClient astclient;

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<SCATests>();

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
        public void ListSCAScanVulnerabilitiesTest()
        {
            var project = astclient.GetAllProjectsDetails().Single(y => y.Name == "java-goof");

            Assert.IsNotNull(project);

            var scaLastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);

            Assert.IsNotNull(scaLastScan);

            var scanDetails = astclient.GetScanDetails(scaLastScan);

            foreach (var finding in scanDetails.SCAVulnerabilities)
            {
                Trace.WriteLine($"Package: {finding.PackageName} " +
                    $"| State: {finding.RiskState} " +
                    $"| Comment: {finding.RiskStateLastUpdateComment} " +
                    $"| Author: {finding.RiskStateLastUpdateUser} " +
                    $"| Version: {finding.PackageVersion} " +
                    $"| Severity: {finding.Severity} " +
                    $"| CveName: {finding.CveName} " +
                    $"| FixResolutionText: {finding.FixResolutionText}");
            }      

        }


        [TestMethod]
        public void GetSCAFindingsTest()
        {

        }

        [TestMethod]
        public void MarkingFindingsTest()
        {
            var project = astclient.GetAllProjectsDetails().Single(y => y.Name == "java-goof");

            Assert.IsNotNull(project);

            var scaLastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);

            Assert.IsNotNull(scaLastScan);

            ScanReportJson lastScanReport = astclient.Requests.GetScanReport(scaLastScan.Id);

            Assert.IsTrue(lastScanReport.Vulnerabilities.Count > 0, "No vulnerabilities found in the last scan report.");

            foreach (var vuln in lastScanReport.Vulnerabilities)
            {
                try
                {
                    astclient.MarkSCAVulnerability(project.Id, vuln, VulnerabilityStatus.ToVerify, "test");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex.Message);
                }
            }

        }
        

    }
}
