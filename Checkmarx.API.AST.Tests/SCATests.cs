using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Models.SCA;
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
                    astclient.MarkSCAVulnerability(project.Id, vuln, ScaVulnerabilityStatus.Confirmed, "test");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex.Message);
                }
            }

        }

        [TestMethod]
        public void RecalcMainBranchTest()
        {
            var project = astclient.GetAllProjectsDetails().Single(y => y.Name == "java-goof");

            Trace.WriteLine(project.Id);

            Assert.IsNotNull(project);

            var scan = astclient.Scans.RecalculateAsync(new Services.Scans.RecalculateInput
            {
                Project_id = project.Id,
                Branch = project.MainBranch,
                Engines = ["sca"]
            }, "custom-auto-scan").Result;

            Assert.IsNotNull(scan);

            Trace.WriteLine(scan.Id);
        }

        [TestMethod]
        public void CheckForNewResultsTest()
        {
            var projects = astclient.GetAllProjectsDetails().Where(x => x.Name == "BB::ASPLATFORM::NewCVE-Custom01");

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

                    foreach (var scaVulnerability in scaDetails.SCAVulnerabilities
                        .Where(x => x.RiskStatus == Services.Results.StatusEnum.NEW))
                    {
                        Trace.WriteLine(project.Name + " " + scaLastScan.Id + " " + scaVulnerability.Id + " " + scaVulnerability.PackageName);
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex.Message);
                }
            }


        }

        [TestMethod]
        public void GetLastScanFromSpecificTagTest()
        {

            var lastProductionScan = astclient.GetScans(
                new Guid("0c136f2c-5bc1-4612-9828-e204da11fc8f"),
                branch: "master", scanKind: Checkmarx.API.AST.Enums.ScanRetrieveKind.Last, tagKeys: ["SHA256"], completed: false).SingleOrDefault();


            Assert.IsNotNull(lastProductionScan);

            Trace.WriteLine(lastProductionScan.Id);

        }

        [TestMethod]
        public void GetLibrariesInTheInventoryTest()
        {
            var projects = astclient.GraphQLClient.GetSCAProjectsThanContainLibraryAsync("org.springframework.security:spring-security-core", ["6.4.3"]);

            var allProjects = astclient.GetAllProjectsDetails().ToDictionary(x => x.Id);

            foreach (var packages in projects)
            {



                var project = allProjects[packages.ProjectId];

                var projectlink = project.GetLink(astclient.ASTServer);

                var scan = astclient.GetScanDetails(packages.ScanId);

                Trace.WriteLine($"{project.Name} -> {project.MainBranch}; ScanBranch: {scan.Branch}");
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


        /// <summary>
        /// Creates a list of consecutive pairs from the input list.
        /// Each pair consists of (element[i], element[i+1]).
        /// </summary>
        /// <typeparam name="T">The type of objects in the list.</typeparam>
        /// <param name="source">The input list of objects.</param>
        /// <returns>A list of tuples, where each tuple represents a pair of consecutive elements.</returns>
        /// <remarks>
        /// If the input list has fewer than 2 elements, an empty list of pairs will be returned.
        /// </remarks>
        public static List<(T First, T Second)> GetConsecutivePairs<T>(IList<T> source)
        {
            // Handle null source list gracefully
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source), "The source list cannot be null.");
            }

            // If the list has less than 2 elements, no pairs can be formed.
            if (source.Count < 2)
            {
                return new List<(T First, T Second)>();
            }

            var pairs = new List<(T First, T Second)>();

            // Iterate from the first element up to the second-to-last element
            for (int i = 0; i < source.Count - 1; i++)
            {
                pairs.Add((source[i], source[i + 1]));
            }

            return pairs;
        }

        [TestMethod]
        public void GetScanCompareTest()
        {
            foreach (var proj in astclient.GetAllProjectsDetails())
            {
                foreach (var branch in astclient.GetProjectBranches(proj.Id))
                {
                    // get scans
                    var allScaScans = astclient.GetScans(
                        proj.Id,
                        branch: branch,
                        engine: ASTClient.SCA_Engine)
                        .Reverse()
                        .Select(x => astclient.GetScanDetails(x)).ToList();

                    if (allScaScans.Count() > 1)
                    {
                        foreach (var scaScanPair in GetConsecutivePairs<ScanDetails>(allScaScans))
                        {
                            foreach (var diff in ASTClient.GetNewSCAVulnerabilities(
                                scaScanPair.First.SCAVulnerabilities, scaScanPair.Second.SCAVulnerabilities))
                            {
                                Trace.WriteLine($"{proj.Name} -  {branch} - {scaScanPair.Second.Id} - New: {diff.CveName} - {diff.RiskStatus.ToString()}");
                            }
                        }
                    }
                }
            }
        }


        [TestMethod]
        public void GetSCADiffTest()
        {
            var scan1 = astclient.GetScanDetails(new Guid("25731032-2394-479b-b9ca-72d0e15188ad"));
            var scan2 = astclient.GetScanDetails(new Guid("9a0fc7dd-b1d8-47ae-9e94-20f925a4caeb"));

            Trace.WriteLine($"Scan: {scan2.SCAVulnerabilities.Count()}");

            var grousByRiskStatus = scan2.SCAVulnerabilities
                .GroupBy(x => x.Severity);

            foreach (var risk in grousByRiskStatus)
            {
                Trace.WriteLine($"{risk.Key.ToString()}: {risk.Count()}");
            }


            foreach (var diff in ASTClient.GetNewSCAVulnerabilities(
                               scan1.SCAVulnerabilities, scan2.SCAVulnerabilities))
            {
                Trace.WriteLine($"{diff.RiskStatus.ToString()}: {diff.CveName}");
            }

        }

    }
}
