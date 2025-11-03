using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Analytics;
using Checkmarx.API.AST.Services.Projects;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AnalyticsTests
    {
        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }

        public static IEnumerable<Guid> projectIds = [
            new Guid("4a0737cc-3057-49eb-b04f-7c643d98458e"),
            new Guid("2112442a-cd06-408d-bb66-b92e5dc61024"),
            new Guid("929369b4-80b2-4344-9469-033222ef00f2")
        ];

        public static DateTime StartDate = DateTime.UtcNow.AddMonths(-6);
        public static DateTime EndDate = DateTime.UtcNow;

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

            Configuration = builder.Build();

            string astServer = Configuration["ASTServer"];
            string accessControl = Configuration["AccessControlServer"];

            astclient = new ASTClient(
                new System.Uri(astServer),
                new System.Uri(accessControl),
                Configuration["Tenant"],
                Configuration["API_KEY"]);
        }

        [TestMethod]
        public void VulnerabilitiesBySeverityTotalTest()
        {
            try
            {
                var result = astclient.GetAnalyticsVulnerabilitiesBySeverityTotal(StartDate, EndDate, null);

                Trace.WriteLine($"LoC: {result.Loc}");
                Trace.WriteLine($"Total: {result.Total}");
                foreach (var data in result.Distribution)
                    Trace.WriteLine($"Label: {data.Label} | Density: {data.Density} | Percentage: {data.Percentage} | Results: {data.Results}");
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Vulnerabilities By Severity Total report: {ex.Message}");
            }
        }

        [TestMethod]
        public void VulnerabilitiesBySeverityTotalWithOptionsTest()
        {
            try
            {
                var result = astclient.GetAnalyticsVulnerabilitiesBySeverityTotal(StartDate, EndDate, new Models.AnalyticsOptions()
                {
                    Projects = projectIds.ToList(),
                    Scanners = new List<ScannerType>() { ScannerType.Sast },
                });

                Trace.WriteLine($"LoC: {result.Loc}");
                Trace.WriteLine($"Total: {result.Total}");
                foreach (var data in result.Distribution)
                    Trace.WriteLine($"Label: {data.Label} | Density: {data.Density} | Percentage: {data.Percentage} | Results: {data.Results}");
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Vulnerabilities By Severity Total report: {ex.Message}");
            }
        }

        [TestMethod]
        public void VulnerabilitiesBySeverityOvertimeTest()
        {
            try
            {
                var result = astclient.GetAnalyticsVulnerabilitiesBySeverityOvertime(StartDate, EndDate, null);

                foreach (var data in result.Distribution)
                {
                    Trace.WriteLine($"Label: {data.Label}");
                    foreach (var value in data.Values)
                    {
                        Trace.WriteLine($"Time: {value.Time} | Value: {value.Value} | Date: {value.Date}");
                    }
                    Trace.WriteLine("");
                }

            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Vulnerabilities By Severity Overtime report: {ex.Message}");
            }
        }

        [TestMethod]
        public void VulnerabilitiesByStateTotalTest()
        {
            try
            {
                var result = astclient.GetAnalyticsVulnerabilitiesByStateTotal(StartDate, EndDate, null);

                Trace.WriteLine($"LoC: {result.Loc}");
                Trace.WriteLine($"Total: {result.Total}");
                foreach (var data in result.Distribution)
                    Trace.WriteLine($"Label: {data.Label} | Density: {data.Density} | Percentage: {data.Percentage} | Results: {data.Results}");
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Vulnerabilities By State Total report: {ex.Message}");
            }
        }

        [TestMethod]
        public void VulnerabilitiesBySeverityAndStateTotalTest()
        {
            try
            {
                var result = astclient.GetAnalyticsVulnerabilitiesBySeverityAndStateTotal(StartDate, EndDate, null);

                foreach (var data in result)
                {
                    Trace.WriteLine($"Label: {data.Label}");
                    Trace.WriteLine($"Results: {data.Results}");
                    foreach (var severity in data.Severities)
                    {
                        Trace.WriteLine($"Label: {severity.Label} | Results: {severity.Results}");
                    }
                    Trace.WriteLine("");
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Vulnerabilities By Severity And State Total report: {ex.Message}");
            }
        }

        [TestMethod]
        public void AnalyticsAgingTotalTest()
        {
            try
            {
                var result = astclient.GetAnalyticsAgingTotal(StartDate, EndDate, null);

                foreach (var data in result.AgingAndSeverities)
                {
                    Trace.WriteLine($"Label: {data.Label}");
                    Trace.WriteLine($"Results: {data.Results}");
                    foreach (var severity in data.Severities)
                    {
                        Trace.WriteLine($"Label: {severity.Label} | Results: {severity.Results}");
                    }
                    Trace.WriteLine("");
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Aging Total report: {ex.Message}");
            }
        }

        [TestMethod]
        public void AnalyticsIdeTotalTest()
        {
            try
            {
                var result = astclient.GetAnalyticsIdeTotal(StartDate, EndDate, null);

                foreach (var data in result.IdeData)
                    Trace.WriteLine($"Label: {data.Label} | Scans: {data.Scans} | Developers: {data.Developers}");
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Ide Total report: {ex.Message}");
            }
        }

        [TestMethod]
        public void AnalyticsIdeOvertimeTest()
        {
            try
            {
                var result = astclient.GetAnalyticsIdeOvertime(StartDate, EndDate, null);

                foreach (var data in result.Distribution)
                {
                    Trace.WriteLine($"Label: {data.Label}");
                    foreach (var value in data.Values)
                        Trace.WriteLine($"Time: {value.Time} | Scans: {value.Scans} | Developers: {value.Developers} | Date: {value.Date}");
                    Trace.WriteLine("");
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Ide Overtime report: {ex.Message}");
            }
        }

        [TestMethod]
        public void AnalyticsMostCommonVulnerabilitiesTest()
        {
            try
            {
                var results = astclient.GetAnalyticsMostCommonVulnerabilities(StartDate, EndDate, 10, null);

                foreach (var data in results)
                {
                    Trace.WriteLine($"VulnerabilityName: {data.VulnerabilityName}");
                    Trace.WriteLine($"Total: {data.Total}");
                    foreach (var value in data.Severities)
                        Trace.WriteLine($"Label: {value.Label} | Results: {value.Results}");
                    Trace.WriteLine("");
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Most Common Vulnerabilities report: {ex.Message}");
            }
        }

        [TestMethod]
        public void AnalyticsMostAgingVulnerabilitiesTest()
        {
            try
            {
                var results = astclient.GetAnalyticsMostAgingVulnerabilities(StartDate, EndDate, 10, null);

                foreach (var data in results)
                    Trace.WriteLine($"Label: {data.Label} | Age: {data.Age} | VulnerabilityName: {data.VulnerabilityName}");
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Most Aging Vulnerabilities report: {ex.Message}");
            }
        }

        [TestMethod]
        public void AnalyticsAllVulnerabilitiesTest()
        {
            try
            {
                var results = astclient.GetAnalyticsAllVulnerabilities(StartDate, EndDate, null);

                foreach (var data in results)
                {
                    Trace.WriteLine($"VulnerabilityName: {data.VulnerabilityName} | Scanner: {data.Scanner} | Age: {data.Total}");
                    foreach (var severity in data.Severities)
                        Trace.WriteLine($"Label: {severity.Label} | Results: {severity.Results}");
                    Trace.WriteLine("");
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error getting Most Aging Vulnerabilities report: {ex.Message}");
            }
        }
    }
}
