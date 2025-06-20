using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Polly.Fallback;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

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
            var project = astclient.GetAllProjectsDetails().Single(y => y.Name == "NotificationTest");

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
                    $"| Status: {finding.RiskStatus} " +
                    $"| CveName: {finding.CveName} " +
                    $"| FixResolutionText: {finding.FixResolutionText}");
               
            }

        }

        [TestMethod]
        public void ListCVENamesTest()
        {

            var project = astclient.GetAllProjectsDetails().Single(y => y.Name == "java-goof");

            Assert.IsNotNull(project);

            var scaLastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);

            Assert.IsNotNull(scaLastScan);

            var scanDetails = astclient.GetScanDetails(scaLastScan);


            var listOfCVEs = scanDetails.SCAVulnerabilities.Select(x => x.CveName).Distinct();

            //foreach (var cveId in listOfCVEs)
            //{
            //    Trace.WriteLine(cveId);
            //}

            foreach (var cveId in listOfCVEs)
            {
                try
                {
                    Trace.WriteLine(cveId);

                    var cveDefinition = astclient.SCA.GetCVEDefinitionAsync(cveId).Result;

                    Trace.WriteLine($"Help Link: {cveDefinition.GetLink(astclient.ASTServer)}");

                    Trace.WriteLine($"Vulnerability ID: {cveDefinition.CveName}");
                    Trace.WriteLine($"CVSS Score: {cveDefinition.Score}");
                    Trace.WriteLine($"Severity: {cveDefinition.Severity}");
                    Trace.WriteLine($"CWE ID: {cveDefinition.Cwe}");
                    Trace.WriteLine($"EPSS Score: {cveDefinition.Epss?.EpssEpss:P0}");
                    Trace.WriteLine($"KEV: {cveDefinition.Kev != null}");
                    Trace.WriteLine($"POC: {cveDefinition.ExploitDb != null}");
                    Trace.WriteLine($"Publish Date: {cveDefinition.PublishDate}");
                    Trace.WriteLine($"Description: {cveDefinition.Description}");
                    Trace.WriteLine("---------------------------------------------------");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Error fetching CVE definition for {cveId}: {ex.Message} {ex.StackTrace}");
                }
            }
        }

        [TestMethod]
        public void GetSCAFindingsHistoryTest()
        {
            var project = astclient.GetAllProjectsDetails().Single(y => y.Name == "nodejs-goof");

            Assert.IsNotNull(project);

            var scaLastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);

            Assert.IsNotNull(scaLastScan);

            var scanDetails = astclient.GetScanDetails(scaLastScan);

            foreach (var finding in scanDetails.SCAVulnerabilities)
            {
                var result = astclient.GraphQLClient.GetFindingsChangeHistoryAsync(
                    project.Id,
                    scaLastScan.Id,
                    finding.PackageName,
                    finding.PackageVersion,
                    finding.PackageManager,
                    finding.Id).Result;

                Trace.WriteLine(result);

                break;

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
                    astclient.MarkSCAVulnerability(project.Id, vuln, VulnerabilityStatus.Confirmed, "test");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex.Message);
                }
            }

        }

        [TestMethod]
        public void RecalcTest()
        {
            var project = astclient.GetAllProjectsDetails().Single(y => y.Name == "java-goof");

            Trace.WriteLine(project.Id);

            Assert.IsNotNull(project);

            return;

            var scaLastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);

            Assert.IsNotNull(scaLastScan);

            var scan = astclient.Scans.RecalculateAsync(new Services.Scans.RecalculateInput
            {
                Project_id = project.Id,
                Branch = scaLastScan.Branch,
                Engines = ["sca"]
            }).Result;

            Assert.IsNotNull(scan);

            Trace.WriteLine(scan.Id);
        }

        [TestMethod]
        public void CheckForNewResultsTest()
        {
            var projects = astclient.GetAllProjectsDetails();

            foreach (var project in projects)
            {
                Assert.IsNotNull(project);

                var scaLastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);

                if (scaLastScan == null)
                    continue;
                try
                {

                    Trace.WriteLine(scaLastScan.Metadata.Type);

                    var scaDetails = astclient.GetScanDetails(scaLastScan); // Ensure the scan details are fetched first

                    foreach (var scaVulnerability in scaDetails.SCAVulnerabilities.Where(x => x.RiskStatus == Services.Results.StatusEnum.NEW))
                    {
                        Trace.WriteLine(project.Name + " " + scaLastScan.Id);
                        break;
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex.Message);
                }
            }


        }

        [TestMethod]
        public void GetLibrariesInTheInventoryTest()
        {
            string cveId = "CVE-2020-1938";

            var projects = astclient.GraphQLClient.GetSCAProjectsThanContainLibraryAsync("jquery", ["3.4.1"]);

            var allProjects = astclient.GetAllProjectsDetails().ToDictionary(x => x.Id);

            foreach (var packages in projects.Result.Data.ReportingPackages.Select(x => x.ProjectId).Distinct())
            {
                var project = allProjects[packages];
                var projectlink = project.GetLink(astclient.ASTServer);

                Trace.WriteLine(project.Name  + " " + projectlink.AbsoluteUri);
            }

            
        }

        [TestMethod]
        public void GetCVEDefinitionTest()
        {
            string cveId = "CVE-2020-1938";

            var cveDefinition = astclient.SCA.GetCVEDefinitionAsync(cveId).Result;

            Trace.WriteLine($"Help Link: {cveDefinition.GetLink(astclient.ASTServer)}");

            Trace.WriteLine($"Vulnerability ID: {cveDefinition.CveName}");
            Trace.WriteLine($"CVSS Score: {cveDefinition.Score}");
            Trace.WriteLine($"Severity: {cveDefinition.Severity}");
            Trace.WriteLine($"CWE ID: {cveDefinition.Cwe}");
            Trace.WriteLine($"EPSS Score: {cveDefinition.Epss.EpssEpss:P0}");
            Trace.WriteLine($"KEV: {cveDefinition.Kev != null}");
            Trace.WriteLine($"POC: {cveDefinition.ExploitDb != null}");
            Trace.WriteLine($"Publish Date: {cveDefinition.PublishDate}");
            Trace.WriteLine($"Description: {cveDefinition.Description}");
        }
    }
}
