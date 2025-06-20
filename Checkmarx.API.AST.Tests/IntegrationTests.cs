using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class IntegrationTests
    {
        public static IConfigurationRoot Configuration { get; private set; }

        private static ASTClient astclient;

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<IntegrationTests>();

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
        public void ListProjectProfilesTest()
        {
            Dictionary<string, ICollection<string>> emailstoNotify = astclient.Integrations.GetEmailsToNotifyForSCANewVuln();

            Dictionary<Guid, string> projectProfiles = astclient.Integrations.GetProjectProfiles();

            foreach (var proj in astclient.GetAllProjectsDetails())
            {
                if (projectProfiles.ContainsKey(proj.Id))
                {
                    var profileName = projectProfiles[proj.Id];

                    Trace.WriteLine($"Project: {proj.Name} - Profile: {profileName}");

                    if (emailstoNotify.ContainsKey(profileName))
                    {
                        emailstoNotify[profileName].ToList().ForEach(email => Trace.WriteLine("\t" + email));
                    }
                }
                else
                {
                    Trace.WriteLine($"Project: {proj.Name} - Profile: Not Found");
                }
            }
        }

        [TestMethod]
        public void ListProfilesTest()
        {

        }

        [TestMethod]
        public void ListFeedbackAppsTest()
        {
            var faconfiguration = astclient.Integrations.GetFeedbackAppAsync(22164).Result;

            Trace.WriteLine($"Id: {faconfiguration.Id} - Name: {faconfiguration.Name} - Description: {faconfiguration.Description}");

            foreach (var email in faconfiguration.Configuration.Emails)
            {
                Trace.WriteLine(email);
            }
        }

        [TestMethod]
        public void GetFeedbackAppCollectionTest()
        {
            // Dictionary<FeedbackApp> -> ICollection of Emails
            Dictionary<string, List<string>> profileEmails = new Dictionary<string, List<string>>(StringComparer.InvariantCultureIgnoreCase);

            // Get only the Email notification SCA New Vulnerability 
            foreach (var feedbackApp in astclient.Integrations.GetFeedbackAppCollectionAsync().Result.Apps)
            {
                Trace.WriteLine($"Id: {feedbackApp.Id} - Name: {feedbackApp.Name} - Type: {feedbackApp.Type} - TriggerCondition: {feedbackApp.TriggerCondition}");

                var app = astclient.Integrations.GetFeedbackAppAsync(feedbackApp.Id).Result;

                foreach (var email in app.Configuration.Emails)
                {
                    Trace.WriteLine("\t" + email);
                }
            }

        }

    }
}
