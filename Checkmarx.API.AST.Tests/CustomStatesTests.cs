using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class CustomStatesTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

            Configuration = builder.Build();

            Assert.IsNull(Configuration["API_KEY"]);

            astclient = new ASTClient(
            new System.Uri(Configuration["ASTServer"]),
            new System.Uri(Configuration["AccessControlServer"]),
            Configuration["Tenant"],
            Configuration["API_KEY"]);
        }

        [TestMethod]
        public void ListCustomStatesTest()
        {
            var customStates = astclient.GetAllCustomStates();
            foreach (var item in customStates)
                Trace.WriteLine($"Custom State: {item.Name} ({item.Id})");
        }

        [TestMethod]
        public void CreateCustomStateTest()
        {
            astclient.CreateNewCustomState("NewStateToDelete");
        }

        [TestMethod]
        public void DeleteCustomStateTest()
        {
            astclient.DeleteCustomState("NewStateToDelete");
        }
    }
}
