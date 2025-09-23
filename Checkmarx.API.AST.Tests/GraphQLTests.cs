using Checkmarx.API.AST.Models.SCA;
using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests;

[TestClass]
public class GraphQLTests
{
    public static IConfigurationRoot Configuration { get; private set; }

    private static ASTClient astclient;

    [ClassInitialize]
    public static void InitializeTest(TestContext testContext)
    {
        var builder = new ConfigurationBuilder()
            .AddUserSecrets<GraphQLTests>();

        Configuration = builder.Build();

        Assert.IsNotNull(Configuration["API_KEY"]);

        astclient = new ASTClient(
        new System.Uri(Configuration["ASTServer"]),
        new System.Uri(Configuration["AccessControlServer"]),
        Configuration["Tenant"],
        Configuration["API_KEY"]);
    }

    [TestMethod]
    public void GetSCAVulnerabilityHistoryTest()
    {
        var variables = new Models.SCA.PackageVulnerabilityStateAndScoreActionsVariables
        {
            ScanId = new Guid("f283a7e6-0840-4110-bcf4-ab8e884a47f4"),
            ProjectId = new Guid("7efd49f4-ffe3-486f-b330-876a9e7a6326"),
            IsLatest = true,
            PackageName = "org.apache.commons:commons-text",
            PackageVersion = "1.9",
            PackageManager = "Maven",
            VulnerabilityId = "CVE-2022-42889"
        };

        var result = astclient.GraphQLClient.SearchPackageVulnerabilityActionsAsync(variables).Result;

        foreach (var item in result)
            Trace.WriteLine($"ActionType: {item.ActionType} | Value: {item.ActionValue} | Date: {item.CreatedAt}");
    }

    [TestMethod]
    public void MigrateSCAPredicateTest()
    {
        var scanId = Guid.Parse("22b9bc3a-463c-43d8-8875-b1d64ab870bf");

        var projectId = astclient.GetScanDetails(scanId).ProjectId;

        var variables = new Models.SCA.PackageVulnerabilityStateAndScoreActionsVariables
        {
            ScanId = scanId,
            ProjectId = projectId,
            IsLatest = true,
            PackageName = "com.fasterxml.jackson.core:jackson-core",
            PackageVersion = "2.6.5",
            PackageManager = "Maven",
            VulnerabilityId = "CVE-2016-7051"
        };

        var target = new ScaPackageInfo
        {
            ProjectIds = [projectId],
            PackageManager = "Maven",
            PackageName = "com.fasterxml.jackson.core:jackson-databind",
            PackageVersion = "2.6.5",
            VulnerabilityId = "CVE-2019-14540"
        };

        var result = astclient.GraphQLClient.SearchPackageVulnerabilityActionsAsync(variables).Result;

        foreach (var item in result.Reverse<ScaActionItem>())
        {
            Trace.WriteLine($"{item.ActionType} {item.CreatedAt}");

            var actions = new List<ActionType>();

            switch (item.ActionType)
            {
                case ActionTypeEnum.ChangeState:
                case ActionTypeEnum.ChangeScore:
                    {
                        actions.Add(new ActionType
                        {
                            Type = item.ActionType,
                            Value = item.ActionValue,
                            Comment = item.Comment.Message
                        });
                    }
                    break;
                case ActionTypeEnum.GroupStateAndScoreActions:
                    {
                        var state = item.ActionValue.Split('|')[0];
                        var score = item.ActionValue.Split('|')[1];

                        actions.Add(new ActionType
                        {
                            Type = ActionTypeEnum.ChangeState,
                            Value = state,
                            Comment = item.Comment.Message
                        });

                        actions.Add(new ActionType
                        {
                            Type = ActionTypeEnum.ChangeScore,
                            Value = score,
                            Comment = item.Comment.Message
                        });
                    }
                    break;
                default:
                    throw new NotSupportedException($"Unknown action type: {item.ActionType}");
            }

            target.Actions = actions.ToArray();

            astclient.SCA.UpdateResultState(target).Wait();
        }

        Assert.IsNotNull(result);
    }


    [TestMethod]
    public void GetAllRisksByScanIdTest()
    {
        var scanId = Guid.Parse("22b9bc3a-463c-43d8-8875-b1d64ab870bf");

        var projectId = astclient.GetScanDetails(scanId).ProjectId;

        var result = astclient.GraphQLClient.GetAllVulnerabilitiesRisksByScanIdAsync(new Models.SCA.VulnerabilitiesRisksByScanIdVariables
        {
            ScanId = scanId,
            IsExploitablePathEnabled = false
        }).Result;

        var groupedBySeverity = result.GroupBy(x => x.Severity);

        foreach (var severity in groupedBySeverity)
        {
            Trace.WriteLine($"{severity.Key} -> {severity.Count()}");
        }

        foreach (var item in result)
        {
            var variables = new Models.SCA.PackageVulnerabilityStateAndScoreActionsVariables
            {
                ScanId = scanId,
                ProjectId = projectId,
                IsLatest = true,
                PackageName = item.PackageInfo.Name,
                PackageVersion = item.PackageInfo.Version,
                PackageManager = item.PackageInfo.PackageRepository,
                VulnerabilityId = item.Cve
            };

            var predicates = astclient.GraphQLClient.SearchPackageVulnerabilityActionsAsync(variables).Result;


            Trace.WriteLine($"Package: {item.Cve} | State : {item.State} | Changes: {predicates.Count()}");

        }

        Assert.IsNotNull(result);
    }


    [TestMethod]
    public void MarkSCATest()
    {

        var scanId = Guid.Parse("22b9bc3a-463c-43d8-8875-b1d64ab870bf");

        var projectId = astclient.GetScanDetails(scanId).ProjectId;

        var list = astclient.GraphQLClient.GetAllVulnerabilitiesRisksByScanIdAsync(new Models.SCA.VulnerabilitiesRisksByScanIdVariables
        {
            ScanId = scanId,
            IsExploitablePathEnabled = false
        }).Result;

        var vulnerabilityRisk = list.First();

        for (int i = 0; i < 10; i++)
        {
            foreach (var status in Enum.GetValues<ScaVulnerabilityStatus>())
            {
                astclient.SCA.UpdateResultState(new ScaPackageInfo
                {
                    PackageManager = vulnerabilityRisk.PackageInfo.PackageRepository,
                    PackageName = vulnerabilityRisk.PackageInfo.Name,
                    PackageVersion = vulnerabilityRisk.PackageInfo.Version,
                    VulnerabilityId = vulnerabilityRisk.Cve,
                    ProjectIds = [projectId],
                    Actions = [
                    new ActionType
                    {
                        Type = ActionTypeEnum.ChangeState,
                        Value = status.ToString(),
                        Comment = $"Change state to {status}"
                    }
               ],
                }).Wait();
            }
        }

    }


}



