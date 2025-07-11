using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Checkmarx.API.AST.Tests;

[TestClass]
public class APIRisksTest
{
    private static ASTClient astclient;

    public static IConfigurationRoot Configuration { get; private set; }


    [ClassInitialize]
    public static void InitializeTest(TestContext testContext)
    {
        var builder = new ConfigurationBuilder()
            .AddUserSecrets<APIRisksTest>();

        Configuration = builder.Build();

        Assert.IsNotNull(Configuration["API_KEY"]);

        astclient = new ASTClient(
        new System.Uri(Configuration["ASTServer"]),
        new System.Uri(Configuration["AccessControlServer"]),
        Configuration["Tenant"],
        Configuration["API_KEY"]);
    }

    [TestMethod]
    public void GetRisksTest()
    {
        var results = astclient.GetApiRisks(new System.Guid("ce0b5173-c25e-41bf-be75-76bbc5793199"));

        Assert.IsNotNull(results);
    }
}
