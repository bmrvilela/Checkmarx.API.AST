using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Services.SASTQueriesAudit;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class CreditsTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


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
        public void GetInfoTest()
        {
            var info = astclient.Credits.GetInfoAsync().Result;

            Trace.WriteLine($"Credits Info: {info.Total} total, {info.Used} used");
        }

        [TestMethod]
        public void GetLicenseStatusTest()
        {
            var status = astclient.Credits.GetLicenseStatusAsync().Result;

            Assert.IsNotNull(status);
            Trace.WriteLine($"License status: {status.State}, {status.StartDate} - {status.EndDate}");
        }

        [TestMethod]
        public void GetBurnRateTest()
        {
            var burnRate = astclient.Credits.GetBurnRateAsync().Result;

            Assert.IsNotNull(burnRate);
            Trace.WriteLine($"Burn rate: {burnRate.RatePerMonth}/month, depletion {burnRate.EstimatedDepletionDate}");
        }

        [TestMethod]
        public void GetBurnRateTrendTest()
        {
            var trend = astclient.Credits.GetBurnRateTrendAsync(DateTime.Today.AddDays(-30), DateTime.Today).Result;

            Assert.IsNotNull(trend);
            foreach (var item in trend)
                Trace.WriteLine($"{item.Date:yyyy-MM-dd}: {item.TotalCreditsConsumed}");
        }

        [TestMethod]
        public void GetActionRatesTest()
        {
            var rates = astclient.Credits.GetActionRatesAsync().Result;

            Assert.IsNotNull(rates);
            foreach (var rate in rates.Rates)
                Trace.WriteLine($"{rate.DisplayName}: {rate.CreditsPerAction} credits/action");
        }

        [TestMethod]
        public void GetConsumptionByActionTest()
        {
            var consumption = astclient.Credits.GetConsumptionByActionAsync("last_90_days").Result;

            Assert.IsNotNull(consumption);
            foreach (var action in consumption.Actions)
                Trace.WriteLine($"{action.ActionDisplayName}: {action.Count} actions, {action.TotalCredits} credits ({action.Percentage}%)");
        }

        [TestMethod]
        public void GetTopConsumersTest()
        {
            var consumers = astclient.Credits.GetTopConsumersAsync("user", "last_90_days").Result;

            Assert.IsNotNull(consumers);
            foreach (var consumer in consumers.Items)
                Trace.WriteLine($"{consumer.Name}: {consumer.Operations.Sum(o => o.Credits)} credits");
        }
    }
}
