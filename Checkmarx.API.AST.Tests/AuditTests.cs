using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.SASTScanResultsCompare;
using Checkmarx.API.AST.Services.Scans;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AuditTests
    {
        public static IConfigurationRoot Configuration { get; private set; }

        private static ASTClient astclient;

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<AuditTests>();

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
        public void ListAllQueriesTest()
        {
            Assert.Fail();
        }

        [TestMethod]
        public void ListTenantQueriesTest()
        {
            Assert.Fail();
        }

        [TestMethod]
        public void ListProjectQueriesTest()
        {
            Assert.Fail();
        }

        [TestMethod]
        public void OverrideQueryForProjectTest()
        {
            Assert.Fail();
        }

        [TestMethod]
        public void DeleteQueryTest()
        {
            Assert.Fail();
        }

    }
}