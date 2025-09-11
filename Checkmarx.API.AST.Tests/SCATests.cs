using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Models.SCA;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Scans;
using Keycloak.Net.Models.Root;
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
        public void UpdatePackageStateTest()
        {
            Guid projectId = Guid.Parse("852a2366-c1fe-4bfa-af4d-dbb9cb69148c");
            string packageManager = "Npm";
            string packageName = "express-jwt";
            string packageVersion = "0.1.3";

            astclient.MarkSCAPackage(projectId, packageManager, packageName, packageVersion, PackageStateEnum.Snooze, "Test");
        }

        [TestMethod]
        public void ListVulnerabilitiesTest()
        {

            foreach (var risk in astclient.GetScanDetails(Guid.Parse("9ed7a70a-4d56-433c-af04-28250dca8a17")).SCAVulnerabilities)
            {
                Trace.WriteLine($"{risk.CveName} - {risk.RiskState} - {risk.RiskStatus} - {risk.PackageName}");
            }
        }

        [TestMethod]
        public void ListRisksTest()
        {
            foreach (var risk in astclient.GetScanDetails(Guid.Parse("9ed7a70a-4d56-433c-af04-28250dca8a17")).SCA_Risks)
            {
                Trace.WriteLine($"{risk.Cve} - {risk.PackageState.Value} - {risk.State}");
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
        public void RefreshGITest()
        {
            foreach (var project in astclient.GetAllProjectsDetails())
            {
                Trace.WriteLine(project.Id + " " + project.Name);

                var lastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca, completed: true, branch: project.MainBranch);

                if (lastScan != null)
                {
                    var scan = astclient.Scans.RecalculateAsync(new Services.Scans.RecalculateInput
                    {
                        Project_id = project.Id,
                        Branch = lastScan.Branch,
                        Engines = ["sca"]
                    }, "gi-ref").Result;

                    Assert.IsNotNull(scan);
                }
            }
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
            var scan2 = astclient.GetScanDetails(new Guid("daead9f6-67b4-498c-9db8-b282dfa27034")); // 59
            var scan1 = astclient.GetScanDetails(new Guid("b915a759-b33f-43f2-9d59-48d88eb388ce")); // 58

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

        [TestMethod]
        public void ListPackageCVETest()
        {
            var results = astclient.SCA.GetPackageRisks(["Npm#-#cx-dummy-package#-#1.0.0"]).Result;
            var risks = astclient.GetScanDetails(new Guid("1e827e52-1f7a-46d0-a904-f202085b14e1")).SCA_Risks.Select(x => x.Cve).ToHashSet();

            Trace.WriteLine("Total Package Risks: " + results.Count());
            Trace.WriteLine($"Total Risks: {risks.Count()}");

            foreach (var cve in results)
            {
                var cveDef = astclient.SCA.GetCVEDefinitionAsync(cve.Cve).Result;

                Trace.WriteLine($"CVE: {cveDef.CveName} {cveDef.Id == Guid.Empty} {cveDef.GetLink(astclient.ASTServer)}] ");
            }
        }


        [TestMethod]
        public void ListCxDummyPackageRisksTest()
        {
            var results = astclient.SCA.GetPackageRisks(["Npm#-#cx-dummy-package#-#1.0.0"]).Result;

            Trace.WriteLine("Total Package Risks: " + results.Count());
            foreach (var cve in results)
            {
                Trace.WriteLine($"CVE: {cve.Cve}");
            }
        }

        [TestMethod]
        public void ListKnownCVEwithSeverityTest()
        {
            var results = astclient.GraphQLClient.GetAllVulnerabilitiesAsync().Result.GroupBy(x => x.State);

            Trace.WriteLine($"Total CVEs: {results.Count()}");

            foreach (var item in results)
            {
                Trace.WriteLine(item.Key);
            }
        }

        [TestMethod]
        public void InjectNewCVETest()
        {
            var severityToCreate = "Critical";

            var existentRisks = astclient.GraphQLClient.GetAllVulnerabilitiesAsync(10000).Result
                .Where(x => x.VulnerabilityId.StartsWith("CVE-") && 
                x.Severity == severityToCreate);

            var cxDummyPackageRisks = astclient.SCA
                .GetPackageRisks(["Npm#-#cx-dummy-package#-#1.0.0"]).Result
                .Select(x => x.Cve).ToHashSet();

            string newCVE = null;

            Parallel.ForEach(existentRisks, new ParallelOptions { MaxDegreeOfParallelism = 100 }, cve =>
            {
                newCVE = cve.VulnerabilityId;

                var cveDef = astclient.SCA.GetCVEDefinitionAsync(newCVE).Result;

                if (!cxDummyPackageRisks.Contains(newCVE) && cveDef.Id != Guid.Empty)
                {
                    Trace.WriteLine(newCVE);
                }
            });

            Trace.WriteLine($"CVE added to cx-dummy-package: {newCVE}");

            //astclient.SCA.InjectNewCVE(newCVE).Wait();
        }

        [TestMethod]
        public void DeleteCVETest()
        {
            astclient.SCA.DeleteCVE("CVE-2021-21347").Wait();
        }

        [TestMethod]
        public void MyTestMethod()
        {
            var scan = astclient.Scans.GetScanAsync(Guid.Parse("2b07dfbf-9643-4fda-8e69-013097563956")).Result;

            Assert.IsNotNull(scan, "Scan should not be null");

            processScan(scan);
        }

        private void processScan(Scan scan)
        {
            var projectDetails = astclient.GetProject(scan.ProjectId);
            var scanDetails = astclient.GetScanDetails(scan.Id);

            // Check if Main Branch is defined. If it is, we only process the scan it is from the main branch
            // If there is no Main branch defined, continue the process
            if (!string.IsNullOrWhiteSpace(projectDetails.MainBranch) && scan.Branch != projectDetails.MainBranch)
            {
                Trace.TraceWarning($"Skipping scan ({scan.Id}) from project {scan.ProjectId}:: MainBranch is {projectDetails.MainBranch} and scan branch is not ({scan.Branch}).");
                return;
            }

            // Validate if it has new SCA vulnerabilities
            int newVulnerabilities = scanDetails.SCAVulnerabilities.Where(x => x.RiskStatus == Checkmarx.API.AST.Services.Results.StatusEnum.NEW).Count();

            #region Clone Metadata & Update Date Tag

            // get scan tags from the last production scan with the tags
            var lastProductionScan = astclient.GetScans(scan.ProjectId, engine: "sca", branch: scan.Branch, scanKind: Checkmarx.API.AST.Enums.ScanRetrieveKind.Last, tagKeys: ["PRD_DATE"], completed: false).SingleOrDefault();

            Trace.WriteLine(lastProductionScan.Id);

            if (lastProductionScan == null)
            {
                Trace.TraceWarning($"No production scan found for project {projectDetails.Name} and branch {scan.Branch}.");
                return;
            }

            if (newVulnerabilities == 0)
            {
                newVulnerabilities = ASTClient.GetNewSCAVulnerabilities(astclient.GetScanDetails(lastProductionScan).SCAVulnerabilities, scanDetails.SCAVulnerabilities).Count();

                if (newVulnerabilities == 0)
                {
                    Trace.TraceWarning($"Project {projectDetails.Name} Scan {scanDetails.Id} has NO NEW SCA vulnerabilities. Process terminated.");
                    return;
                }
            }

            if (newVulnerabilities > 0)
            {
                Trace.TraceWarning($"Project {projectDetails.Name} Scan {scanDetails.Id} has new SCA vulnerabilities. Updating tags...");

                var tagResult = astclient.Scans.GetTagsAsync(lastProductionScan.Id).Result;
                var lastProductionScanTags = tagResult.Tags;
                if (!lastProductionScanTags.ContainsKey("OrigScanId"))
                {
                    lastProductionScanTags.Add("OrigScanId", lastProductionScan.Id.ToString());
                }

                // clone the tags to the latest scan
                astclient.Scans.UpdateTagsAsync(scanDetails.Id, new ModifyScanTagsInput
                {
                    Tags = lastProductionScanTags
                });
            }

            #endregion
        }

    }
}
