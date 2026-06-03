using Checkmarx.API.AST.Services.ReportsV2;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ReportsV2Tests
    {
        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ReportsV2Tests>();

            Configuration = builder.Build();

            if (!string.IsNullOrWhiteSpace(Configuration["API_KEY"]))
            {
                astclient = new ASTClient(
                    new Uri(Configuration["ASTServer"]),
                    new Uri(Configuration["AccessControlServer"]),
                    Configuration["Tenant"],
                    Configuration["API_KEY"]);
            }
            else
            {
                astclient = new ASTClient(
                    new Uri(Configuration["ASTServer"]),
                    new Uri(Configuration["AccessControlServer"]),
                    Configuration["Tenant"],
                    Configuration["ClientId"],
                    Configuration["ClientSecret"]);
            }
        }

        [TestMethod]
        public void ConnectTest()
        {
            Assert.IsTrue(astclient.Connected);
        }

        /// <summary>
        /// Creates an improved scan report (PDF) for a given scan ID and logs the returned reportId.
        /// Replace the scanId below with a valid scan ID from your tenant.
        /// </summary>
        [TestMethod]
        public void CreateImprovedScanReportTest()
        {
            var scanId = Configuration["TestScanId"] ?? throw new InvalidOperationException("Set TestScanId in user secrets.");

            var request = new CreateScanReportV2Request
            {
                ReportName = "improved-scan-report",
                ReportType = ReportV2Type.Cli,
                FileFormat = ScanReportV2FileFormat.Pdf,
                Entities = new List<ReportV2Entity>
                {
                    new ReportV2Entity
                    {
                        Entity = ReportV2EntityType.Scan,
                        Ids = new List<string> { scanId }
                    }
                },
                Filters = new ReportV2Filters
                {
                    Scanners = new List<string> { "sast", "sca", "iac" },
                    Severities = new List<string> { "critical", "high", "medium" },
                    States = new List<string> { "to-verify", "confirmed", "urgent" },
                    Status = new List<string> { "new", "recurrent" }
                }
            };

            var response = astclient.ReportsV2.CreateScanReportAsync(request).Result;

            Assert.IsNotNull(response);
            Assert.AreNotEqual(Guid.Empty, response.ReportId);

            Trace.WriteLine($"Improved Scan Report created. ReportId: {response.ReportId}");
        }

        /// <summary>
        /// Creates an improved scan report in JSON format with specific sections.
        /// Replace the scanId below with a valid scan ID from your tenant.
        /// </summary>
        [TestMethod]
        public void CreateImprovedScanReportJsonWithSectionsTest()
        {
            var scanId = Configuration["TestScanId"] ?? throw new InvalidOperationException("Set TestScanId in user secrets.");

            var request = new CreateScanReportV2Request
            {
                ReportName = "improved-scan-report",
                ReportType = ReportV2Type.Cli,
                FileFormat = ScanReportV2FileFormat.Json,
                Sections = new List<string>
                {
                    ReportV2Sections.ScanInformation,
                    ReportV2Sections.ResultsOverview,
                    ReportV2Sections.ScanResults
                },
                Entities = new List<ReportV2Entity>
                {
                    new ReportV2Entity
                    {
                        Entity = ReportV2EntityType.Scan,
                        Ids = new List<string> { scanId }
                    }
                },
                Filters = new ReportV2Filters
                {
                    Scanners = new List<string> { "sast" },
                    Severities = new List<string> { "critical", "high" },
                    States = new List<string> { "to-verify", "confirmed" }
                }
            };

            var response = astclient.ReportsV2.CreateScanReportAsync(request).Result;

            Assert.IsNotNull(response);
            Assert.AreNotEqual(Guid.Empty, response.ReportId);

            Trace.WriteLine($"Improved Scan Report (JSON) created. ReportId: {response.ReportId}");
        }

        /// <summary>
        /// Creates an improved project report (PDF) for a given project ID.
        /// Replace the projectId below with a valid project ID from your tenant.
        /// </summary>
        [TestMethod]
        public void CreateImprovedProjectReportTest()
        {
            var projectId = Configuration["TestProjectId"] ?? throw new InvalidOperationException("Set TestProjectId in user secrets.");

            var request = new CreateProjectReportV2Request
            {
                ReportName = "improved-project-report",
                ReportType = ReportV2Type.Cli,
                FileFormat = ProjectReportV2FileFormat.Pdf,
                Sections = new List<string>
                {
                    ReportV2Sections.ProjectsOverview,
                    ReportV2Sections.TotalVulnerabilitiesOverview,
                    ReportV2Sections.VulnerabilitiesInsights
                },
                Entities = new List<ReportV2Entity>
                {
                    new ReportV2Entity
                    {
                        Entity = ReportV2EntityType.Project,
                        Ids = new List<string> { projectId },
                        Tags = new List<string>()
                    }
                },
                Filters = new ReportV2Filters
                {
                    Scanners = new List<string> { "sast", "iac", "sca" },
                    Severities = new List<string> { "critical", "high", "medium" },
                    States = new List<string> { "to-verify", "confirmed", "urgent" },
                    Status = new List<string> { "new", "recurrent" }
                }
            };

            var response = astclient.ReportsV2.CreateProjectReportAsync(request).Result;

            Assert.IsNotNull(response);
            Assert.AreNotEqual(Guid.Empty, response.ReportId);

            Trace.WriteLine($"Improved Project Report created. ReportId: {response.ReportId}");
        }

        /// <summary>
        /// Creates an improved project report for multiple projects.
        /// Replace the project IDs below with valid project IDs from your tenant.
        /// </summary>
        [TestMethod]
        public void CreateImprovedProjectReportMultipleProjectsTest()
        {
            var projectId = Configuration["TestProjectId"] ?? throw new InvalidOperationException("Set TestProjectId in user secrets.");

            var request = new CreateProjectReportV2Request
            {
                ReportName = "improved-project-report",
                ReportType = ReportV2Type.Ui,
                FileFormat = ProjectReportV2FileFormat.Pdf,
                Entities = new List<ReportV2Entity>
                {
                    new ReportV2Entity
                    {
                        Entity = ReportV2EntityType.Project,
                        Ids = new List<string> { projectId },
                        Tags = new List<string>()
                    }
                },
                Filters = new ReportV2Filters
                {
                    Scanners = new List<string> { "sast", "sca" },
                    Severities = new List<string> { "critical", "high" },
                    States = new List<string> { "confirmed", "urgent" },
                    Status = new List<string> { "new" }
                }
            };

            var response = astclient.ReportsV2.CreateProjectReportAsync(request).Result;

            Assert.IsNotNull(response);
            Assert.AreNotEqual(Guid.Empty, response.ReportId);

            Trace.WriteLine($"Improved Project Report (multi) created. ReportId: {response.ReportId}");
        }
    }
}
