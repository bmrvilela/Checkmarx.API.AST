
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ASTUnitTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ASTUnitTests>();

            Configuration = builder.Build();

            astclient = new ASTClient(
                new System.Uri(Configuration["ASTServer"]),
                new System.Uri(Configuration["AccessControlServer"]), 
                Configuration["Tenant"], 
                Configuration["API_KEY"]);
        }

        [TestMethod]
        public void ConnectTest()
        {
            Assert.IsTrue(astclient.Connected);
        }

        [TestMethod]
        public void ListProjects()
        {
            Assert.IsNotNull(astclient.Projects);

            var projectsList = astclient.Projects.GetListOfProjectsAsync().Result;

            foreach (var item in projectsList.Projects)
            {
                Trace.WriteLine(item.Id + " " + item.Name + " " + item.RepoUrl);
            }
        }

        [TestMethod]
        public void ListApplications()
        {
            Assert.IsNotNull(astclient.Applications);

            var applicationsList = astclient.Applications.GetListOfApplicationsAsync().Result;

            foreach (var item in applicationsList.Applications)
            {
                Trace.WriteLine(item.Id + " " + item.Name);
            }
        }

        [TestMethod]
        public void ListScansTest()
        {
            Assert.IsNotNull(astclient.Scans);

            var scansList = astclient.Scans.GetListOfScansAsync("1c724868-72fa-4bfe-aca5-6c9096b48408").Result;

            foreach (var item in scansList.Scans)
            {
                Trace.WriteLine(item.Id + " " + item.ProjectId);
            }
        }


        [TestMethod]
        public void GetResultsByScanTest()
        {

        }

        [TestMethod]
        public void GetSASTResultsByScanTest()
        {

        }
    }
}
