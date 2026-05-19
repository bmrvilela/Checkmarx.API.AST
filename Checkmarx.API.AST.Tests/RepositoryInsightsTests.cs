using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class RepositoryInsightsTests
    {
        public static IConfigurationRoot Configuration { get; private set; }

        private static ASTClient astclient;

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
        public void GetRepositoriesByProjectTest()
        {
            var projectList = astclient.Projects.GetListOfProjectsAsync().Result;
            if (projectList?.Projects == null || !projectList.Projects.Any())
            {
                Trace.WriteLine("No projects found.");
                return;
            }

            var projectId = projectList.Projects.First().Id.ToString();
            var result = astclient.RepositoryInsights.GetRepositoriesByProjectAsync(projectId, limit: 10).Result;

            Assert.IsNotNull(result, "Project response should not be null.");

            Trace.WriteLine($"Project: {result.ProjectName} ({result.ProjectId})");
            Trace.WriteLine($"Last scan: {result.LastScanDate}");
            Trace.WriteLine($"Total LOC: {result.TotalLoc}");
            Trace.WriteLine($"Total scanned files: {result.TotalScannedFiles}");
            Trace.WriteLine($"Total unscanned files: {result.TotalUnscannedFiles}");
            Trace.WriteLine($"Total repositories: {result.TotalRepositories} | Page: {result.Page}");

            if (result.Repositories != null)
            {
                foreach (var repo in result.Repositories)
                {
                    Trace.WriteLine($"  Repo: {repo.RepositoryUrl}" +
                        $" | Last scan: {repo.LastScanDate}" +
                        $" | Scanned files: {repo.ScannedFiles}" +
                        $" | Unscanned files: {repo.UnscannedFiles}");
                }
            }
        }

        [TestMethod]
        public void GetRepositoriesByProjectWithPaginationTest()
        {
            var projectList = astclient.Projects.GetListOfProjectsAsync().Result;
            if (projectList?.Projects == null || !projectList.Projects.Any())
            {
                Trace.WriteLine("No projects found.");
                return;
            }

            var projectId = projectList.Projects.First().Id.ToString();

            var page1 = astclient.RepositoryInsights.GetRepositoriesByProjectAsync(projectId, offset: 0, limit: 5).Result;
            Assert.IsNotNull(page1);
            Trace.WriteLine($"Page 1: {page1.Repositories?.Count ?? 0} repositories, total: {page1.TotalRepositories}");

            if (page1.TotalRepositories > 5)
            {
                var page2 = astclient.RepositoryInsights.GetRepositoriesByProjectAsync(projectId, offset: 5, limit: 5).Result;
                Assert.IsNotNull(page2);
                Trace.WriteLine($"Page 2: {page2.Repositories?.Count ?? 0} repositories");
            }
        }

        [TestMethod]
        public void GetInsightsByRepositoryTest()
        {
            var projectList = astclient.Projects.GetListOfProjectsAsync().Result;
            if (projectList?.Projects == null || !projectList.Projects.Any())
            {
                Trace.WriteLine("No projects found.");
                return;
            }

            var projectId = projectList.Projects.First().Id.ToString();
            var projectRepos = astclient.RepositoryInsights.GetRepositoriesByProjectAsync(projectId, limit: 1).Result;

            if (projectRepos?.Repositories == null || projectRepos.Repositories.Count == 0)
            {
                Trace.WriteLine("No repositories found for the project.");
                return;
            }

            var repoUrl = projectRepos.Repositories.First().RepositoryUrl;
            Trace.WriteLine($"Fetching insights for: {repoUrl}");

            var result = astclient.RepositoryInsights.GetInsightsByRepositoryAsync(repoUrl).Result;

            Assert.IsNotNull(result, "Repository insights response should not be null.");

            Trace.WriteLine($"Repository: {result.RepositoryURL}");
            Trace.WriteLine($"Last scan date: {result.LastScanDate}");
            Trace.WriteLine($"Scan ID: {result.ScanID}");

            if (result.Insights?.SAST != null)
            {
                var sast = result.Insights.SAST;
                Trace.WriteLine($"SAST - Scanned files: {sast.ScannedFiles}" +
                    $" | Unscanned: {sast.UnscannedFiles}" +
                    $" | LOC: {sast.TotalScannedLOC}");
                if (sast.Languages != null)
                    Trace.WriteLine($"SAST - Languages: {string.Join(", ", sast.Languages)}");
                if (!string.IsNullOrEmpty(sast.Error))
                    Trace.WriteLine($"SAST - Error: {sast.Error}");
            }

            if (result.Insights?.KICS != null)
            {
                var kics = result.Insights.KICS;
                Trace.WriteLine($"KICS - Scanned files: {kics.ScannedFiles}" +
                    $" | Unscanned: {kics.UnscannedFiles}" +
                    $" | LOC: {kics.TotalScannedLOC}");
                if (!string.IsNullOrEmpty(kics.Error))
                    Trace.WriteLine($"KICS - Error: {kics.Error}");
            }

            if (result.Insights?.RecentCommits != null)
            {
                var commits = result.Insights.RecentCommits;
                Trace.WriteLine($"Commits - Total: {commits.TotalCommits}" +
                    $" | Last commit: {commits.LastCommitDate}");
                if (!string.IsNullOrEmpty(commits.Warning))
                    Trace.WriteLine($"Commits - Warning: {commits.Warning}");
                if (!string.IsNullOrEmpty(commits.Error))
                    Trace.WriteLine($"Commits - Error: {commits.Error}");
            }
        }
    }
}
