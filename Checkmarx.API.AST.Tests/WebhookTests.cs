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
    public class WebhookTests
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
        public void GetWebHooksTest()
        {
            var webhooks = astclient.GetWebhooks();

            foreach (var wh in webhooks)
            {
                Trace.WriteLine($"Id: {wh.Id} " +
                    $"| Name: {wh.Name} " +
                    $"| Url: {wh.Config.Url} " +
                    $"| Enabled Events: {string.Join(", ", wh.EnabledEvents)} " +
                    $"| Active: {wh.Active}");
            }
        }

        [TestMethod]
        public void CreateWebHookTest()
        {
            List<ASTClient.WebhookEventType> enabledEvents = new List<ASTClient.WebhookEventType>() { ASTClient.WebhookEventType.scan_completed_successfully };

            astclient.CreateWebhook("Test Webhook",
                                    "https://example.com/webhook",
                                    "123456",
                                    enabledEvents);
        }

        [TestMethod]
        public void UpdateWebHookTest()
        {
            var webhooks = astclient.GetWebhooks();
            var testwh = webhooks.FirstOrDefault(x => x.Name == "Test Webhook");
            if (testwh != null)
            {
                List<ASTClient.WebhookEventType> enabledEvents = new List<ASTClient.WebhookEventType>()
                {
                    ASTClient.WebhookEventType.scan_completed_successfully,
                    ASTClient.WebhookEventType.scan_failed,
                    ASTClient.WebhookEventType.scan_partial
                };

                astclient.UpdateWebhook(testwh.Id,
                                        testwh.Name,
                                        "https://example.com/webhook2",
                                        "123456",
                                        enabledEvents);
            }
        }

        [TestMethod]
        public void DeleteWebHookTest()
        {
            var webhooks = astclient.GetWebhooks();
            var testwh = webhooks.FirstOrDefault(x => x.Name == "Test Webhook");
            if (testwh == null)
                throw new Exception("Webhook not found");

            astclient.DeleteWebhook(testwh.Id);
        }
    }
}
