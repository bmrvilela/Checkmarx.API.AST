﻿using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Applications;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.Projects;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.Repostore;
using Checkmarx.API.AST.Services.ResultsOverview;
using Checkmarx.API.AST.Services.ResultsSummary;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTQueriesAudit;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using Checkmarx.API.AST.Services.ScannersResults;
using Checkmarx.API.AST.Services.Scans;
using Checkmarx.API.AST.Services.Uploads;
using Checkmarx.API.AST.Services.SASTScanResultsCompare;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Polly;
using Polly.Extensions.Http;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Checkmarx.API.AST.Services.QueryEditor;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Checkmarx.API.AST
{
    public struct CxOneConnection
    {
        public Uri CxOneServer;
        public Uri AccessControlServer;
        public string Tenant;
        public string ApiKey;
    }

    public class ASTClient
    {
        public Uri AccessControlServer { get; private set; }
        public Uri ASTServer { get; private set; }
        public string Tenant { get; }
        public string KeyApi { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        private readonly HttpClient _httpClient = new HttpClient();

        // Helper method to clone HttpRequestMessage
        public static HttpRequestMessage CloneHttpRequestMessage(HttpRequestMessage request)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri);

            // Clone request content (if any)
            if (request.Content != null)
            {
                clone.Content = getHttpContentClone(request.Content);
                clone.Content.Headers.Clear();
                foreach (var header in request.Content.Headers)
                    clone.Content.Headers.Add(header.Key, header.Value);
            }

            // Clone the request headers
            foreach (var header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            // Copy other properties (e.g., Version)
            clone.Version = request.Version;

            return clone;
        }

        private static HttpContent getHttpContentClone(HttpContent content)
        {
            if (content == null)
                throw new ArgumentNullException(nameof(content));

            if (content is StreamContent)
            {
                return new StreamContent(content.ReadAsStreamAsync().Result);
            }
            else if (content is StringContent)
            {
                return new StringContent(content.ReadAsStringAsync().Result);
            }
            else if (content is ByteArrayContent)
            {
                return new ByteArrayContent(content.ReadAsByteArrayAsync().Result);
            }
            else if (content is FormUrlEncodedContent)
            {
                return new FormUrlEncodedContent(content.ReadAsStringAsync().Result.Split('&').Select(pair =>
                {
                    var kv = pair.Split('=');
                    return new KeyValuePair<string, string>(kv[0], kv.Length > 1 ? kv[1] : "");
                }));
            }
            else if (content is MultipartFormDataContent)
            {
                var multiPartContent = (MultipartFormDataContent)content;
                var newMultipartContent = new MultipartFormDataContent();
                foreach (var partContent in multiPartContent)
                {
                    newMultipartContent.Add(partContent, partContent.Headers.ContentDisposition.Name, partContent.Headers.ContentDisposition.FileName);
                }
                return newMultipartContent;
            }
            else
            {
                throw new NotSupportedException($"Unsupported content type: {content.GetType()}");
            }
        }

        internal static readonly IAsyncPolicy<HttpResponseMessage> _retryPolicy = HttpPolicyExtensions
                                .HandleTransientHttpError()
                                .WaitAndRetryAsync(10, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)),
                                (exception, timeSpan, retryCount, context) =>
                                {
                                    // Optional: Log the retry attempt
                                    Console.WriteLine($"Retry {retryCount} after {timeSpan.TotalSeconds} seconds due to: " +
                                        $"{(exception.Exception != null ? exception.Exception.Message : $"{(int?)exception.Result?.StatusCode} {exception.Result?.ReasonPhrase}")}");
                                });

        public const string SettingsAPISecuritySwaggerFolderFileFilter = "scan.config.apisec.swaggerFilter";
        public const string SettingsProjectRepoUrl = "scan.handler.git.repository";
        public const string SettingsProjectExclusions = "scan.config.sast.filter";
        public const string SettingsProjectConfiguration = "scan.config.sast.languageMode";
        public const string SettingsProjectPreset = "scan.config.sast.presetName";
        public const string FastScanConfiguration = "scan.config.sast.fastScanMode";
        public const string IsIncrementalConfiguration = "scan.config.sast.incremental";

        public const string SAST_Engine = "sast";
        public const string SCA_Engine = "sca";
        public const string KICS_Engine = "kics";
        public const string API_Security_Engine = "apisec";
        public const string SCA_Container_Engine = "sca-container";

        private readonly static string CompletedStage = Checkmarx.API.AST.Services.Scans.Status.Completed.ToString();

        #region Services

        private GraphQLClient _graphql;
        public GraphQLClient GraphQLClient
        {
            get
            {
                if (Connected && _graphql == null)
                    _graphql = new GraphQLClient($"{ASTServer.AbsoluteUri}api/sca/graphql/graphql", _httpClient);

                return _graphql;
            }
        }

        private Projects _projects;
        public Projects Projects
        {
            get
            {
                if (Connected && _projects == null)
                    _projects = new Projects($"{ASTServer.AbsoluteUri}api/projects", _httpClient);

                return _projects;
            }
        }

        private FeatureFlags _featureFlags;
        public FeatureFlags FeatureFlags
        {
            get
            {
                if (Connected && _featureFlags == null)
                    _featureFlags = new FeatureFlags(ASTServer, _httpClient);

                return _featureFlags;
            }
        }

        private Lists _lists;
        public Lists Lists
        {
            get
            {
                if (Connected && _lists == null)
                    _lists = new Lists(ASTServer, _httpClient);

                return _lists;
            }
        }

        private Scans _scans;
        public Scans Scans
        {
            get
            {
                if (Connected && _scans == null)
                    _scans = new Scans($"{ASTServer.AbsoluteUri}api/scans", _httpClient);

                return _scans;
            }
        }

        private Reports _reports;
        public Reports Reports
        {
            get
            {
                if (Connected && _reports == null)
                    _reports = new Reports($"{ASTServer.AbsoluteUri}api/reports", _httpClient);

                return _reports;
            }
        }

        private Requests _requests;
        public Requests Requests
        {
            get
            {
                if (Connected && _requests == null)
                    _requests = new Requests(ASTServer, _httpClient);

                return _requests;
            }
        }


        private AccessManagement _accessManagement;
        public AccessManagement AccessManagement
        {
            get
            {
                if (Connected && _accessManagement == null)
                    _accessManagement = new AccessManagement(ASTServer, _httpClient);

                return _accessManagement;
            }
        }


        private SASTMetadata _SASTMetadata;
        public SASTMetadata SASTMetadata
        {
            get
            {
                if (Connected && _SASTMetadata == null)
                    _SASTMetadata = new SASTMetadata($"{ASTServer.AbsoluteUri}api/sast-metadata", _httpClient);

                return _SASTMetadata;
            }
        }

        private Applications _applications;
        public Applications Applications
        {
            get
            {
                if (Connected && _applications == null)
                    _applications = new Applications($"{ASTServer.AbsoluteUri}api/applications", _httpClient);

                return _applications;
            }
        }


        private SASTResults _SASTResults;

        /// <summary>
        /// Engine SAST results
        /// </summary>
        public SASTResults SASTResults
        {
            get
            {
                if (Connected && _SASTResults == null)
                    _SASTResults = new SASTResults(ASTServer, _httpClient);

                return _SASTResults;
            }
        }


        private SASTResultsPredicates _SASTResultsPredicates;

        /// <summary>
        /// Engine SAST results Predicates
        /// </summary>
        public SASTResultsPredicates SASTResultsPredicates
        {
            get
            {
                if (Connected && _SASTResultsPredicates == null)
                    _SASTResultsPredicates = new SASTResultsPredicates(ASTServer, _httpClient);



                return _SASTResultsPredicates;
            }
        }

        private SASTScanResultsCompare _SASTScanResultsCompare;

        /// <summary>
        /// SAST Scan Results Compare
        /// </summary>
        public SASTScanResultsCompare SASTScanResultsCompare
        {
            get
            {
                if (Connected && _SASTScanResultsCompare == null)
                    _SASTScanResultsCompare = new SASTScanResultsCompare(ASTServer, _httpClient);

                return _SASTScanResultsCompare;
            }
        }


        private KicsResults _kicsResults;

        /// <summary>
        /// KICS results
        /// </summary>
        public KicsResults KicsResults
        {
            get
            {
                if (Connected && _kicsResults == null)
                    _kicsResults = new KicsResults($"{ASTServer.AbsoluteUri}api/kics-results", _httpClient);



                return _kicsResults;
            }
        }

        private KICSResultsPredicates _kicsResultsPredicates;

        /// <summary>
        /// KICS marking/predicates
        /// </summary>
        public KICSResultsPredicates KicsResultsPredicates
        {
            get
            {
                if (Connected && _kicsResultsPredicates == null)
                    _kicsResultsPredicates = new KICSResultsPredicates(ASTServer, _httpClient);



                return _kicsResultsPredicates;
            }
        }

        private CxOneSCA _cxOneSCA;

        /// <summary>
        /// SCA API
        /// </summary>
        public CxOneSCA SCA
        {
            get
            {
                if (Connected && _cxOneSCA == null)
                    _cxOneSCA = new CxOneSCA(ASTServer, _httpClient);

                return _cxOneSCA;
            }
        }

        private ScannersResults _scannersResults;

        /// <summary>
        /// Engine Scanners results
        /// </summary>
        public ScannersResults ScannersResults
        {
            get
            {
                if (Connected && _scannersResults == null)
                    _scannersResults = new ScannersResults($"{ASTServer.AbsoluteUri}api/results", _httpClient);



                return _scannersResults;
            }
        }


        private ResultsSummary _resultsSummary;

        /// <summary>
        /// Engine Results Summary
        /// </summary>
        public ResultsSummary ResultsSummary
        {
            get
            {
                if (Connected && _resultsSummary == null)
                    _resultsSummary = new ResultsSummary($"{ASTServer.AbsoluteUri}api/scan-summary", _httpClient);

                return _resultsSummary;
            }
        }

        private ResultsOverview _resultsOverview;
        public ResultsOverview ResultsOverview
        {
            get
            {
                if (Connected && _resultsOverview == null)
                    _resultsOverview = new ResultsOverview($"{ASTServer.AbsoluteUri}api/results-overview", _httpClient);



                return _resultsOverview;
            }
        }


        private Configuration _configuration;

        /// <summary>
        /// Configurations
        /// </summary>
        public Configuration Configuration
        {
            get
            {
                if (Connected && _configuration == null)
                    _configuration = new Configuration($"{ASTServer.AbsoluteUri}api/configuration", _httpClient);

                return _configuration;
            }
        }

        private Repostore _repostore;

        public Repostore Repostore
        {
            get
            {
                if (Connected && _repostore == null)
                    _repostore = new Repostore($"{ASTServer.AbsoluteUri}api/repostore/code", _httpClient);



                return _repostore;
            }
        }

        private Uploads _uploads;

        public Uploads Uploads
        {
            get
            {
                if (Connected && _uploads == null)
                    _uploads = new Uploads($"{ASTServer.AbsoluteUri}api/uploads", _httpClient);



                return _uploads;
            }
        }

        private PresetManagement _presetManagement;

        public PresetManagement PresetManagement
        {
            get
            {
                if (Connected && _presetManagement == null)
                    _presetManagement = new PresetManagement($"{ASTServer.AbsoluteUri}api/presets", _httpClient);



                return _presetManagement;
            }
        }

        private SASTQueriesAudit _sastQueriesAudit;

        public SASTQueriesAudit SASTQueriesAudit
        {
            get
            {
                if (Connected && _sastQueriesAudit == null)
                    _sastQueriesAudit = new SASTQueriesAudit($"{ASTServer.AbsoluteUri}api/cx-audit", _httpClient);

                return _sastQueriesAudit;
            }
        }

        private QueryEditor _queryEditor;

        public QueryEditor QueryEditor
        {
            get
            {
                if (Connected && _queryEditor == null)
                    _queryEditor = new QueryEditor($"{ASTServer.AbsoluteUri}api/query-editor", _httpClient);

                return _queryEditor;
            }
        }

        #endregion

        #region Connection

        private int _bearerExpiresIn;
        private DateTime _bearerValidTo;

        public bool Connected
        {
            get
            {
                if (_httpClient == null || (_bearerValidTo - DateTime.UtcNow).TotalMinutes < 5)
                {
                    var token = authenticate();
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    _httpClient.DefaultRequestHeaders.ConnectionClose = false; // Explicitly ask to keep connection alive
                    _bearerValidTo = DateTime.UtcNow.AddSeconds(_bearerExpiresIn - 300);
                }
                return true;
            }
        }

        public string authenticate()
        {
            var response = requestAuthenticationToken();
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                JObject accessToken = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                string authToken = ((JProperty)accessToken.First).Value.ToString();
                _bearerExpiresIn = (int)accessToken["expires_in"];
                return authToken;
            }
            throw new Exception(response.Content.ReadAsStringAsync().Result);
        }

        public HttpResponseMessage TestConnection()
        {
            return requestAuthenticationToken();
        }

        private HttpResponseMessage requestAuthenticationToken()
        {
            var identityURL = $"{AccessControlServer.AbsoluteUri}auth/realms/{Tenant}/protocol/openid-connect/token";

            Dictionary<string, string> kv;

            if (!string.IsNullOrWhiteSpace(KeyApi))
            {
                kv = new Dictionary<string, string>
                {
                    { "grant_type", "refresh_token" },
                    { "client_id", "ast-app" },
                    { "refresh_token", $"{KeyApi}" }
                };
            }
            else
            {
                kv = new Dictionary<string, string>
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", $"{ClientId}" },
                    { "client_secret", $"{ClientSecret}" }
                };
            }

            var req = new HttpRequestMessage(HttpMethod.Post, identityURL) { Content = new FormUrlEncodedContent(kv) };
            req.Headers.UserAgent.Add(new ProductInfoHeaderValue("ASAProgramTracker", "1.0"));

            _httpClient.DefaultRequestHeaders.Add("Accept", "*/*");
            var response = _httpClient.SendAsync(req).Result;

            return response;
        }

        #endregion

        #region Client

        public ASTClient(CxOneConnection connectionSettings)
            : this(connectionSettings.CxOneServer, connectionSettings.AccessControlServer, connectionSettings.Tenant, connectionSettings.ApiKey) { }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="astServer">
        /// US Environment - https://ast.checkmarx.net/
        /// EU Environment - https://eu.ast.checkmarx.net/
        /// </param>
        /// <param name="server">
        /// URL
        /// https://eu.iam.checkmarx.net
        /// https://iam.checkmarx.net
        /// </param>
        /// <param name="tenant"></param>
        /// <param name="apiKey"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public ASTClient(Uri astServer, Uri accessControlServer, string tenant, string apiKey)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (accessControlServer == null) throw new ArgumentNullException(nameof(accessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentNullException(nameof(apiKey));

            ASTServer = astServer;
            AccessControlServer = accessControlServer;
            Tenant = tenant;
            KeyApi = apiKey;

        }

        public ASTClient(Uri astServer, Uri accessControlServer, string tenant, string clientId, string clientSecret)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (accessControlServer == null) throw new ArgumentNullException(nameof(accessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));

            ASTServer = astServer;
            AccessControlServer = accessControlServer;
            Tenant = tenant;
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        #endregion

        #region Applications

        // TODO: When this cache should be invalidated
        private Services.Applications.ApplicationsCollection _apps { get; set; }
        public Services.Applications.ApplicationsCollection Apps
        {
            get
            {
                if (_apps == null)
                    _apps = getAllApplications();

                return _apps;
            }
        }

        private Services.Applications.ApplicationsCollection getAllApplications(int limit = 20)
        {
            var listApplications = Applications.GetListOfApplicationsAsync(limit).Result;
            if (listApplications.TotalCount > limit)
            {
                var offset = limit;
                bool cont = true;
                do
                {
                    var next = Applications.GetListOfApplicationsAsync(limit, offset).Result;
                    if (next.Applications.Any())
                    {
                        next.Applications.ToList().ForEach(o => listApplications.Applications.Add(o));
                        offset += limit;

                        if (listApplications.Applications.Count == listApplications.TotalCount) cont = false;
                    }
                    else
                        cont = false;

                } while (cont);
            }

            return listApplications;
        }

        public IEnumerable<Services.Applications.Application> GetProjectApplications(Guid projectId)
        {
            return Apps.Applications?.Where(x => x.ProjectIds.Contains(projectId));
        }

        public Services.Applications.Application GetProjectApplication(Guid projectId)
        {
            return GetProjectApplications(projectId)?.FirstOrDefault();
        }

        #endregion

        #region Projects

        public ICollection<Services.Projects.Project> GetAllProjectsDetails(int startAt = 0, int limit = 500)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var result = new List<Services.Projects.Project>();

            while (true)
            {
                var resultPage = Projects.GetListOfProjectsAsync(limit: limit, offset: startAt).Result;

                if (resultPage.Projects != null)
                    result.AddRange(resultPage.Projects);

                startAt += limit;

                if (resultPage.TotalCount == 0 || resultPage.TotalCount == result.Count)
                    return result;
            }
        }

        public RichProject GetProject(Guid id)
        {
            if (id == Guid.Empty)
                throw new ArgumentNullException(nameof(id));

            return Projects.GetProjectAsync(id).Result;
        }

        public void UpdateProjectTags(Guid projectId, IDictionary<string, string> tags)
        {
            if (tags == null)
                throw new ArgumentNullException(nameof(tags));

            var project = Projects.GetProjectAsync(projectId).Result;
            if (project == null)
                throw new Exception($"No project found with id {projectId}");

            ProjectInput input = new ProjectInput
            {
                Tags = tags,
                Name = project.Name,
                Groups = project.Groups,
                RepoUrl = project.RepoUrl,
                MainBranch = project.MainBranch,
                Origin = project.Origin,
                AdditionalProperties = project.AdditionalProperties
            };

            Projects.UpdateProjectAsync(projectId, input).Wait();
        }

        public IEnumerable<string> GetProjectBranches(Guid projectId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            while (true)
            {
                var response = Projects.BranchesAsync(projectId, startAt, limit).Result;
                foreach (var result in response)
                {
                    yield return result;
                }

                if (response.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        public IEnumerable<KicsResult> GetKicsScanResultsById(Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            while (true)
            {
                var response = KicsResults.GetKICSResultsByScanAsync(scanId, startAt, limit).Result;
                foreach (var result in response.Results)
                {
                    yield return result;
                }

                if (response.Results.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        /// <summary>
        /// For SCA it just returns the vulnerabilities.
        /// </summary>
        /// <param name="scanId">Id of the scan</param>
        /// <param name="engines"></param>
        /// <returns></returns>
        public IEnumerable<ScannerResult> GetScannersResultsById(Guid scanId, params string[] engines)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            int startAt = 0;
            int limit = 500;

            while (true)
            {
                var response = ScannersResults.GetResultsByScanAsync(scanId, startAt, limit).Result;
                foreach (var result in response.Results)
                {
                    if (!engines.Any() || (engines.Any() && engines.Contains(result.Type, StringComparer.InvariantCultureIgnoreCase)))
                        yield return result;
                }

                if (response.Results.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        public IEnumerable<ResultsSummary> GetResultsSummaryById(Guid scanId)
        {
            return ResultsSummary.SummaryByScansIdsAsync(new Guid[] { scanId }, include_files: false,
               include_queries: false,
               include_severity_status: false,
               include_status_counters: false).Result.ScansSummaries;
        }

        public Checkmarx.API.AST.Services.Projects.Project CreateProject(string name, Dictionary<string, string> tags)
        {
            return Projects.CreateProjectAsync(new ProjectInput()
            {
                Name = name,
                Tags = tags
            }).Result;
        }

        public static Uri GetProjectUri(Uri astServer, Guid projectId)
        {
            if (astServer == null)
                throw new ArgumentNullException(nameof(astServer));

            if (projectId == Guid.Empty)
                throw new ArgumentException("Empty is not a valid project Id");

            return new Uri(astServer, $"projects/{projectId.ToString("D")}/overview");
        }

        #endregion

        #region Scans

        #region Source Code 

        public byte[] GetSourceCode(Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            return Repostore.GetSourceCode(scanId).Result;
        }

        /// <summary>
        /// Exports the source code to a zip file defined by the file path
        /// </summary>
        /// <param name="scanId"></param>
        /// <param name="filePath"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public string GetSourceCode(Guid scanId, string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentNullException(nameof(filePath));

            System.IO.File.WriteAllBytes(filePath, GetSourceCode(scanId));

            return Path.GetFullPath(filePath);
        }

        #endregion

        /// <summary>
        /// Get all completed scans from project
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        public IEnumerable<Scan> GetAllScans(Guid projectId, string branch = null)
        {
            return GetScans(projectId, branch: branch);
        }

        private IEnumerable<Scan> getAllScans(Guid projectId, string branch = null, int itemsPerPage = 1000, int startAt = 0)
        {
            while (true)
            {
                var result = Scans.GetListOfScansAsync(projectId, limit: itemsPerPage, offset: startAt, branch: branch).Result;

                foreach (var scan in result.Scans)
                {
                    yield return scan;
                }

                startAt += itemsPerPage;

                if (result.Scans.Count == 0)
                    yield break;
            }
        }

        public IEnumerable<Scan> SearchScans(string initiator = null, string tagKey = null, string sourceOrigin = null, int itemsPerPage = 1000, int startAt = 0)
        {
            string[] tagKeys = null;
            if (!string.IsNullOrWhiteSpace(tagKey))
                tagKeys = [tagKey];

            string[] initiators = null;
            if (!string.IsNullOrWhiteSpace(initiator))
                initiators = [initiator];

            while (true)
            {
                var result = Scans.GetListOfScansAsync(limit: itemsPerPage, offset: startAt, initiators: initiators, tags_keys: tagKeys, source_origin: sourceOrigin).Result;

                foreach (var scan in result.Scans)
                {
                    yield return scan;
                }

                startAt += itemsPerPage;

                if (result.Scans.Count == 0)
                    yield break;
            }
        }

        public Scan GetLastScan(Guid projectId, bool fullScanOnly = false, bool completed = true, string branch = null, ScanTypeEnum scanType = ScanTypeEnum.sast, DateTime? maxScanDate = null)
        {
            if (!fullScanOnly && !maxScanDate.HasValue)
            {
                var scanStatus = completed ? CompletedStage : null;

                var scans = this.Projects.GetProjectLastScan([projectId], scan_status: scanStatus, branch: branch, engine: scanType.ToString()).Result;

                if (scans.ContainsKey(projectId.ToString()))
                    return this.Scans.GetScanAsync(new Guid(scans[projectId.ToString()].Id)).Result;

                return null;
            }
            else
            {
                var scans = GetScans(projectId, scanType.ToString(), completed, branch, ScanRetrieveKind.All, maxScanDate);
                if (fullScanOnly)
                {
                    var fullScans = scans.Where(x => IsScanIncremental(x.Id)).OrderByDescending(x => x.CreatedAt);

                    if (fullScans.Any())
                        return fullScans.FirstOrDefault();
                    else
                        return scans.OrderByDescending(x => x.CreatedAt).FirstOrDefault();
                }
                else
                    return scans.FirstOrDefault();
            }
        }

        public Scan GetFirstSASTScan(Guid projectId, string branch = null)
        {
            var scans = GetScans(projectId, SAST_Engine, true, branch, ScanRetrieveKind.All);
            if (scans.Any())
            {
                var fullScans = scans.Where(x => IsScanIncremental(x.Id)).OrderBy(x => x.CreatedAt);
                if (fullScans.Any())
                    return fullScans.FirstOrDefault();
                else
                    return scans.OrderBy(x => x.CreatedAt).FirstOrDefault();
            }
            else
                return scans.OrderBy(x => x.CreatedAt).FirstOrDefault();
        }

        /// <summary>
        /// Get first locked Scan
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        public Scan GetLockedSASTScan(Guid projectId, string branch = null)
        {
            return GetScans(projectId, SAST_Engine, true, branch, ScanRetrieveKind.Locked).FirstOrDefault();
        }


        private Dictionary<Guid, ScanInfo> _sastScansMetada = new Dictionary<Guid, ScanInfo>();

        /// <summary>
        /// Get list of scans, filtered by engine, completion  and scankind
        /// </summary>
        /// <param name="projectId">Project Id</param>
        /// <param name="engine">Engine</param>
        /// <param name="completed">Retrieves only completed scans</param>
        /// <param name="scanKind">All scans or only the first or last </param>
        /// <param name="maxScanDate">Max scan date, including the date</param>
        /// <param name="minScanDate">Min scan date, including the date</param>
        /// <returns></returns>
        public IEnumerable<Scan> GetScans(Guid projectId, string engine = null, bool completed = true, string branch = null, ScanRetrieveKind scanKind = ScanRetrieveKind.All, DateTime? maxScanDate = null, DateTime? minScanDate = null)
        {
            var scans = getAllScans(projectId, branch);

            List<Scan> list = [];
            if (scans.Any())
            {
                scans = scans.Where(x =>
                    (!completed || x.Status == Status.Completed || x.Status == Status.Partial) &&
                    (string.IsNullOrEmpty(branch) || x.Branch == branch) &&
                    (maxScanDate == null || x.CreatedAt.DateTime <= maxScanDate) &&
                    (minScanDate == null || x.CreatedAt.DateTime >= minScanDate)
                );

                if (engine == null || engine == SAST_Engine)
                    loadSASTMetadataInfoForScans(scans.Select(x => x.Id).ToArray());

                switch (scanKind)
                {
                    case ScanRetrieveKind.First:
                        scans = scans.Skip(Math.Max(0, scans.Count() - 1));
                        break;
                    case ScanRetrieveKind.Last:
                        scans = scans.Take(1);
                        break;
                    case ScanRetrieveKind.All:
                        break;
                }

                foreach (var scan in scans)
                {
                    if (!string.IsNullOrEmpty(engine))
                    {
                        if (scan.Engines != null && scan.Engines.Any(x => x == engine &&
                            (scan.Status == Status.Completed || scan.StatusDetails?.SingleOrDefault(x => x.Name == engine)?.Status == CompletedStage)))
                        {
                            list.Add(scan);
                        }
                    }
                    else
                    {
                        list.Add(scan);
                    }
                }
            }

            return list;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="projectId"></param>
        /// <param name="scanId"></param>
        /// <returns></returns>
        public ScanDetails GetScanDetails(Guid scanId)
        {
            return GetScanDetails(Scans.GetScanAsync(scanId).Result);
        }

        public ScanDetails GetScanDetails(Scan scan)
        {
            if (scan == null)
                throw new ArgumentNullException($"No scan found.");

            return new ScanDetails(this, scan);
        }

        public ReportResults GetCxOneScanJsonReport(Guid projectId, Guid scanId, double secondsBetweenPolls = 0.5)
        {
            TimeSpan poolInverval = TimeSpan.FromSeconds(secondsBetweenPolls);

            ScanReportCreateInput sc = new ScanReportCreateInput
            {
                ReportName = BaseReportCreateInputReportName.ScanReport,
                ReportType = BaseReportCreateInputReportType.Ui,
                FileFormat = BaseReportCreateInputFileFormat.Json,
                Data = new Data
                {
                    ProjectId = projectId,
                    ScanId = scanId
                }
            };

            ReportCreateOutput createReportOutut = Reports.CreateReportAsync(sc).Result;

            if (createReportOutut == null)
                throw new NotSupportedException();

            var createReportId = createReportOutut.ReportId;

            if (createReportId == Guid.Empty)
                throw new Exception($"Error getting Report of Scan {scanId}");

            Guid reportId = createReportId;
            string reportStatus = "Requested";
            string pastReportStatus = reportStatus;
            double aprox_seconds_passed = 0.0;
            Report statusResponse = null;

            do
            {
                System.Threading.Thread.Sleep(poolInverval);
                aprox_seconds_passed += 1.020;

                statusResponse = Reports.GetReportAsync(reportId, true).Result;
                reportId = statusResponse.ReportId;
                reportStatus = statusResponse.Status.ToString();

                if (pastReportStatus != reportStatus)
                {
                    pastReportStatus = reportStatus;
                }

                if (aprox_seconds_passed > 60)
                {
                    throw new TimeoutException("AST Scan json report for project {0} is taking a long time! Try again later.");
                }

                if (reportStatus == "Failed")
                {

                    throw new Exception("AST Scan API says it could not generate a json report for project {0}. You may want to try again later.");
                }

            } while (reportStatus != "Completed");

            var reportString = Reports.DownloadScanReportJsonUrl(statusResponse.Url).Result;

            return JsonConvert.DeserializeObject<ReportResults>(reportString);
        }

        public IEnumerable<SASTResult> GetSASTScanResultsById(Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));


            while (true)
            {
                Services.SASTResults.SASTResultsResponse response = SASTResults.GetSASTResultsByScanAsync(scanId, startAt, limit).Result;

                if (response.Results != null)
                {
                    foreach (var result in response.Results)
                    {
                        yield return result;
                    }

                    if (response.Results.Count() < limit)
                        yield break;

                    startAt += limit;
                }
                else
                {
                    yield break;
                }
            }
        }

        public IEnumerable<SastResultCompare> GetSASTScanCompareResultsByScans(Guid baseScanId, Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            while (true)
            {
                SastResultCompareResponse response = SASTResults.GetSASTResultsCompareByScansAsync(baseScanId, scanId, offset: startAt, limit: limit).Result;

                if (response.Results != null)
                {
                    foreach (var result in response.Results)
                    {
                        yield return result;
                    }

                    if (response.Results.Count() < limit)
                        yield break;

                    startAt += limit;
                }
                else
                {
                    yield break;
                }
            }
        }


        #region ReRun Scans

        public Scan ReRunGitScan(Guid projectId, string repoUrl, IEnumerable<ConfigType> scanTypes, string branch, string preset,
                string configuration = null,
                bool incremental = false,
                Dictionary<string, string> tags = null,
                bool enableFastScan = false)
        {
            ScanInput scanInput = new()
            {
                Project = new Services.Scans.Project()
                {
                    Id = projectId
                },
                Type = ScanInputType.Git,
                Handler = new Git()
                {
                    Branch = branch,
                    RepoUrl = repoUrl
                },
                Config = createScanConfigForAllEngines(scanTypes, preset, configuration, incremental, enableFastScan: enableFastScan)
            };

            if (tags != null)
                scanInput.Tags = tags;

            return Scans.CreateScanAsync(scanInput).Result;

        }

        public Scan ReRunUploadScan(Guid projectId, Guid lastScanId, IEnumerable<ConfigType> scanTypes, string branch, string preset, string configuration = null,
            Dictionary<string, string> tags = null,
            bool? enableFastScan = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (lastScanId == Guid.Empty)
                throw new ArgumentNullException(nameof(lastScanId));

            byte[] source = Repostore.GetSourceCode(lastScanId).Result;

            return RunUploadScan(projectId, source, scanTypes, branch, preset, configuration, tags: tags, enableFastScan: enableFastScan);
        }

        public Scan RunUploadScan(Guid projectId, byte[] source, IEnumerable<ConfigType> scanTypes, string branch, string preset,
            string configuration = null,
            Dictionary<string, string> tags = null,
            bool? enableFastScan = null)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            if (scanTypes == null || !scanTypes.Any())
                throw new ArgumentNullException(nameof(scanTypes));

            string uploadUrl = Uploads.GetPresignedURLForUploading().Result;

            Uploads.SendHTTPRequestByFullURL(uploadUrl, source).Wait();

            ScanUploadInput scanInput = new()
            {
                Project = new Services.Scans.Project()
                {
                    Id = projectId
                },
                Type = ScanInputType.Upload,
                Handler = new Upload()
                {
                    Branch = branch,
                    UploadUrl = uploadUrl
                },
                Config = createScanConfigForAllEngines(scanTypes, preset, configuration, enableFastScan: enableFastScan)
            };

            if (tags != null)
                scanInput.Tags = tags;

            return Scans.CreateScanUploadAsync(scanInput).Result;

        }

        #endregion

        #region Scan Configuration

        private ICollection<Config> createScanConfigForAllEngines(IEnumerable<ConfigType> scanTypes, string preset, string configuration, bool incremental = false, bool? enableFastScan = null)
        {
            var configs = new List<Config>();

            foreach (var scanType in scanTypes)
            {
                var engineConfig = new Config { Type = scanType };

                switch (scanType)
                {
                    case ConfigType.Sca:
                        // engineConfig.Value = getSCAConfiguration();
                        break;
                    case ConfigType.Sast:
                        engineConfig.Value = getSASTScanConfiguration(preset, configuration, incremental, enableFastScan);
                        break;
                    case ConfigType.Kics:
                        // Swagger
                        break;
                    case ConfigType.Microengines:
                        break;
                    case ConfigType.ApiSec:
                        // Swagger File/Folders
                        break;
                    case ConfigType.System:
                        break;
                    default:
                        throw new NotSupportedException($"{scanType}");
                }

                configs.Add(engineConfig);
            }

            return configs;
        }

        private IDictionary<string, string> getSCAConfiguration(bool exploitablePath = false)
        {
            var result = new Dictionary<string, string>()
            {
                ["ExploitablePath"] = exploitablePath.ToString()
            };

            return result;
        }

        private IDictionary<string, string> getSASTScanConfiguration(string preset, string configuration, bool incremental, bool? enableFastScan = null, bool engineVerbose = false)
        {
            var result = new Dictionary<string, string>()
            {
                ["incremental"] = incremental.ToString(),
                ["presetName"] = preset,
                ["engineVerbose"] = engineVerbose.ToString()
            };

            if (!string.IsNullOrEmpty(configuration))
                result.Add("defaultConfig", configuration);

            if (enableFastScan != null)
            {
                result.Add("fastScanMode", enableFastScan.Value.ToString());

                if (enableFastScan.Value)
                    result.Add("languageMode", 5.ToString()); // force to 5...
            }

            return result;
        }

        #endregion

        public void DeleteScan(Guid scanId)
        {
            var scan = Scans.GetScanAsync(scanId).Result;
            if (scan != null)
            {
                if (scan.Status == Status.Running || scan.Status == Status.Queued)
                    CancelScan(scanId);

                Scans.DeleteScanAsync(scanId).Wait();
            }
        }

        public void CancelScan(Guid scanId)
        {
            Scans.CancelScanAsync(scanId, new Body { Status = Status.Canceled.ToString() }).Wait();
        }

        #endregion

        #region Results

        public bool MarkSASTResult(Guid projectId, SASTResult result, IEnumerable<PredicateWithCommentJSON> history, bool updateSeverity = true, bool updateState = true, bool updateComment = true)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (history == null)
                throw new NullReferenceException(nameof(history));

            if (result == null)
                throw new ArgumentNullException(nameof(result));

            List<PredicateBySimiliartyIdBody> body = [];

            foreach (var predicate in history)
            {
                PredicateBySimiliartyIdBody newBody = new PredicateBySimiliartyIdBody
                {
                    SimilarityId = predicate.SimilarityId.ToString(),
                    ProjectId = projectId,
                    Severity = updateSeverity ? predicate.Severity : result.Severity,
                    State = updateState ? predicate.State : result.State,
                    Comment = updateComment ? predicate.Comment : null
                };

                body.Add(newBody);
            }

            if (body.Any())
            {
                SASTResultsPredicates.PredicateBySimiliartyIdAndProjectIdAsync(body).Wait();
                return true;
            }

            return false;
        }

        public void MarkSASTResult(Guid projectId, string similarityId, ResultsSeverity severity, ResultsState state, string comment = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            PredicateBySimiliartyIdBody newBody = new PredicateBySimiliartyIdBody
            {
                SimilarityId = similarityId,
                ProjectId = projectId,
                Severity = severity,
                State = state
            };

            if (!string.IsNullOrWhiteSpace(comment))
                newBody.Comment = comment;

            SASTResultsPredicates.PredicateBySimiliartyIdAndProjectIdAsync(new PredicateBySimiliartyIdBody[] { newBody }).Wait();
        }

        /// <summary>
        /// Mark IaC, KICS results.
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        public bool MarkKICSResult(Guid projectId, string similarityId, Services.KicsResults.SeverityEnum severity, KicsStateEnum state, string comment = null)
        {
            if (string.IsNullOrWhiteSpace(similarityId))
                throw new ArgumentNullException(nameof(similarityId));

            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            KicsResultsPredicates.UpdateAsync(
                new[] { new POSTPredicate (){
                    SimilarityId = similarityId,
                    ProjectId = projectId,
                    Severity = severity,
                    State = state,
                    Comment = comment
                }
            }).Wait();

            return true;
        }

        public void MarkSCAVulnerability(Guid projectId, Vulnerability vulnerabilityRisk, VulnerabilityStatus vulnerabilityStatus, string message)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (vulnerabilityRisk == null)
                throw new ArgumentNullException(nameof(vulnerabilityRisk));

            if (string.IsNullOrEmpty(message))
                throw new ArgumentNullException(nameof(message));

            SCA.UpdateResultState(new PackageInfo
            {
                PackageManager = vulnerabilityRisk.PackageManager,
                PackageName = vulnerabilityRisk.PackageName,
                PackageVersion = vulnerabilityRisk.PackageVersion,
                VulnerabilityId = vulnerabilityRisk.Id,
                ProjectIds = [projectId],
                Actions = [
                new ActionType
                {
                    Type = ActionTypeEnum.ChangeState,
                    Value = vulnerabilityStatus,
                    Comment = message
                }
            ],
            }).Wait();
        }

        public StatsCompareResult GetScanResultsCompare(Guid baseScanId, Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            if (baseScanId == Guid.Empty)
                throw new ArgumentException(nameof(baseScanId));

            return SASTScanResultsCompare.StatusAsync(baseScanId, scanId).Result;
        }

        #endregion

        #region Configurations

        public void SetProjectConfig(Guid projectId, string key, object value)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException(nameof(key));

            if (value == null)
            {
                Configuration.ProjectDELETEParameterAsync(projectId, key).Wait();
                return;
            }

            List<ScanParameter> body =
            [
                new ScanParameter()
                {
                    Key = key,
                    Value = value.ToString()
                }
            ];

            Configuration.UpdateProjectConfigurationAsync(projectId.ToString(), body).Wait();
        }

        public string GetProjectConfig(Guid projectId, string configKey)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            var configuration = GetProjectConfigurations(projectId);
            if (configuration.ContainsKey(configKey))
            {
                var config = configuration[configKey];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        public string GetScanConfig(Guid projectId, Guid scanId, string configKey)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            var configuration = GetScanConfigurations(projectId, scanId);
            if (configuration.ContainsKey(configKey))
            {
                var config = configuration[configKey];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        public string GetConfigValue(Guid projectId, string configKey)
        {
            string projectConfigValue = GetProjectConfig(projectId, configKey);
            if (string.IsNullOrEmpty(projectConfigValue))
            {
                var tenant_config = GetTenantConfigurations();
                return tenant_config.ContainsKey(configKey) ? tenant_config[configKey].Value : null;
            }

            return projectConfigValue;
        }

        public Dictionary<string, ScanParameter> GetTenantConfigurations()
        {
            return Configuration.TenantAllAsync().Result?.ToDictionary(x => x.Key, y => y);
        }

        public Dictionary<string, ScanParameter> GetProjectConfigurations(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            return Configuration.ProjectAllAsync(projectId).Result?.ToDictionary(x => x.Key, y => y);
        }

        public Dictionary<string, ScanParameter> GetScanConfigurations(Guid projectId, Guid scanId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            return Configuration.ScanAsync(projectId, scanId).Result?.ToDictionary(x => x.Key, y => y);
        }

        public void DeleteTenantConfiguration(string config_keys)
        {
            if (string.IsNullOrWhiteSpace(config_keys))
                throw new ArgumentException(nameof(config_keys));

            Configuration.TenantDELETEParameterAsync(config_keys).Wait();
        }

        public void DeleteProjectConfiguration(Guid projectId, string config_keys)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(config_keys))
                throw new ArgumentException(nameof(config_keys));

            Configuration.ProjectDELETEParameterAsync(projectId, config_keys).Wait();
        }

        public string GetScanPresetFromConfigurations(Guid projectId, Guid scanId) => GetScanConfig(projectId, scanId, SettingsProjectPreset);

        public string GetScanExclusionsFromConfigurations(Guid projectId, Guid scanId) => GetScanConfig(projectId, scanId, SettingsProjectExclusions);

        public IEnumerable<ScanParameter> GetTenantProjectConfigurations()
        {
            return GetTenantConfigurations().Where(x => x.Value.Key == SettingsProjectConfiguration).Select(x => x.Value);
        }

        public string GetProjectRepoUrl(Guid projectId) => GetProjectConfig(projectId, SettingsProjectRepoUrl);

        public string GetProjectConfiguration(Guid projectId) => GetProjectConfig(projectId, SettingsProjectConfiguration);

        public string GetProjectExclusions(Guid projectId) => GetProjectConfig(projectId, SettingsProjectExclusions);

        public string GetProjectAPISecuritySwaggerFolderFileFilter(Guid projectId) => GetProjectConfig(projectId, SettingsAPISecuritySwaggerFolderFileFilter);

        public void SetProjectExclusions(Guid projectId, string exclusions) => SetProjectConfig(projectId, SettingsProjectExclusions, exclusions);

        public Tuple<string, string> GetProjectFilesAndFoldersExclusions(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            var config = GetProjectExclusions(projectId);
            if (!string.IsNullOrWhiteSpace(config))
            {
                char[] delimiters = new[] { ',', ';' };
                var exclusions = config.Split(delimiters, StringSplitOptions.RemoveEmptyEntries).ToList().Select(x => x.Trim());

                var filesList = exclusions.Where(x => x.StartsWith("."));
                var foldersList = exclusions.Where(x => !x.StartsWith("."));

                var files = filesList.Any() ? string.Join(",", filesList) : string.Empty;
                var folders = foldersList.Any() ? string.Join(",", foldersList) : string.Empty;

                return new Tuple<string, string>(files, folders);
            }

            return new Tuple<string, string>(string.Empty, string.Empty);
        }

        public string GetTenantAPISecuritySwaggerFolderFileFilter()
        {
            var configuration = GetTenantConfigurations();
            if (configuration.ContainsKey(SettingsAPISecuritySwaggerFolderFileFilter))
            {
                var config = configuration[SettingsAPISecuritySwaggerFolderFileFilter];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        public void SetTenantAPISecuritySwaggerFolderFileFilter(string filter = null, bool allowOverride = false)
        {
            if (filter == null)
            {
                // Delete current value
                DeleteTenantConfiguration(SettingsAPISecuritySwaggerFolderFileFilter);
                return;
            }

            List<ScanParameter> body = new List<ScanParameter>() {
                new ScanParameter()
                {
                    Key = SettingsAPISecuritySwaggerFolderFileFilter,
                    Value = filter,
                    AllowOverride = allowOverride
                }
            };

            Configuration.UpdateTenantConfigurationAsync(body).Wait();
        }

        public void SetProjectAPISecuritySwaggerFolderFileFilter(Guid projectId, string filter = null, bool allowOverride = false)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (filter == null)
            {
                // Delete current parameter
                DeleteProjectConfiguration(projectId, SettingsAPISecuritySwaggerFolderFileFilter);
                return;
            }

            List<ScanParameter> body = new List<ScanParameter>() {
                new ScanParameter()
                {
                    Key = SettingsAPISecuritySwaggerFolderFileFilter,
                    Value = filter,
                    AllowOverride = allowOverride
                }
            };

            Configuration.UpdateProjectConfigurationAsync(projectId.ToString(), body).Wait();
        }

        public async Task<Dictionary<Guid, string>> GetScanEngineVersionAsync(IEnumerable<Guid> scans)
        {
            if (scans == null || !scans.Any())
                throw new ArgumentNullException(nameof(scans));

            Dictionary<Guid, string> engineVersions = scans.ToDictionary(x => x, x => (string)null);

            int batchSize = 10;
            List<Task<IEnumerable<ScanEngineVersionInfo>>> tasks = new List<Task<IEnumerable<ScanEngineVersionInfo>>>();

            foreach (var batch in scans.Chunk(batchSize))
            {
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        return await SASTMetadata.EngineVersionAsync(batch);
                    }
                    catch (Exceptions.ApiException apiEx)
                    {
                        if (apiEx.StatusCode == 404)
                            return Enumerable.Empty<ScanEngineVersionInfo>();
                        else
                            throw;
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);

            foreach (var engineVersionsResult in results)
            {
                foreach (var result in engineVersionsResult)
                    engineVersions[result.ScanId] = result.EngineVersion;
            }

            return engineVersions;
        }


        #endregion

        #region Queries and Presets

        public IEnumerable<PresetDetails> GetAllPresetsDetails()
        {
            foreach (var preset in GetAllPresets())
            {
                yield return PresetManagement.GetPresetById(preset.Id).Result;
            }
        }

        public IEnumerable<PresetSummary> GetAllPresets(int limit = 20)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var listPresets = PresetManagement.GetPresetsAsync(limit).Result;
            if (listPresets.TotalCount > limit)
            {
                var offset = limit;
                bool cont = true;
                do
                {
                    var next = PresetManagement.GetPresetsAsync(limit, offset).Result;
                    if (next.Presets.Any())
                    {
                        next.Presets.ToList().ForEach(o => listPresets.Presets.Add(o));
                        offset += limit;

                        if (listPresets.Presets.Count == listPresets.TotalCount) cont = false;
                    }
                    else
                        cont = false;

                } while (cont);
            }

            return listPresets.Presets;
        }

        public IEnumerable<Services.SASTQueriesAudit.Queries> GetTenantQueries()
        {
            return SASTQueriesAudit.QueriesAllAsync().Result;
        }

        public Dictionary<string, Services.SASTQueriesAudit.Queries> GetProjectQueries(Guid projectId)
        {
            // The Distinct is a workaround... not the solution.
            return SASTQueriesAudit.QueriesAllAsync(projectId).Result.DistinctBy(x => x.Id).ToDictionary(x => x.Id, StringComparer.InvariantCultureIgnoreCase);
        }

        public IEnumerable<Services.SASTQueriesAudit.Queries> GetTeamCorpLevelQueries(Guid projectId)
        {
            return SASTQueriesAudit.QueriesAllAsync(projectId).Result.Where(x => x.IsExecutable);
        }

        #region QueryEditor

        Dictionary<Guid, Dictionary<Guid, Guid>> _queryEditorSessionCache = new Dictionary<Guid, Dictionary<Guid, Guid>>();
        private Guid getQueryEditorSessionId(Guid projectId, Guid scanId)
        {
            if (_queryEditorSessionCache.ContainsKey(projectId))
            {
                if (!_queryEditorSessionCache[projectId].ContainsKey(scanId))
                {
                    var sessionId = createNewSessionId(projectId, scanId);
                    _queryEditorSessionCache[projectId].Add(scanId, sessionId);
                }
                else
                {
                    bool errorSession = false;
                    try
                    {
                        QueryEditor.PingSessionAsync(_queryEditorSessionCache[projectId][scanId]).ConfigureAwait(false);
                    }
                    catch
                    {
                        errorSession = true;
                    }

                    if (errorSession)
                    {
                        var sessionId = createNewSessionId(projectId, scanId);
                        _queryEditorSessionCache[projectId][scanId] = sessionId;
                    }
                }
            }
            else
            {
                var sessionId = createNewSessionId(projectId, scanId);
                _queryEditorSessionCache[projectId] = new Dictionary<Guid, Guid>() { { scanId, sessionId } };
            }

            return _queryEditorSessionCache[projectId][scanId];
        }

        public Guid createNewSessionId(Guid projectId, Guid scanId)
        {
            var session = QueryEditor.CreateSessionAsync(new Services.QueryEditor.SessionRequest() { ProjectId = projectId, ScanId = scanId, Scanner = "sast", Timeout = 3000 }).Result;

            bool completed = false;
            Guid? id = null;
            while (!completed)
            {
                System.Threading.Thread.Sleep(5 * 1000);

                var status = QueryEditor.CheckRequestSessionStatusAsync(session.Id, session.Data.RequestID.Value).Result;

                if (status.Completed)
                {
                    completed = true;
                    if (status.Status == RequestStatusStatus.Finished)
                        id = session.Id;
                    else
                        throw new Exception($"Error creating session for project {projectId} with status \"{status.Status.ToString()}\".");
                }
            }

            if (id == null)
                throw new Exception($"Unknown error creating session for project {projectId}");


            return id.Value;
        }

        private void endQueryEditorSessions()
        {
            foreach (var project in _queryEditorSessionCache)
            {
                foreach (var session in project.Value)
                {
                    try
                    {
                        QueryEditor.DeleteSessionAsync(session.Value).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        Trace.WriteLine($"Error ending queryEditor session for project {project.Key}");
                    }
                }
            }

            _queryEditorSessionCache.Clear();
        }

        public IEnumerable<Services.QueryEditor.QueriesTree> GetProjectScanQueryNodes(Guid projectId, Guid scanId)
        {
            var session = getQueryEditorSessionId(projectId, scanId);

            return QueryEditor.GetQueriesAsync(session).Result;
        }

        public Services.QueryEditor.QueryResponse GetProjectQueryByEditorQuery(Guid projectId, Guid scanId, string editorQueryId, bool includeMetadata = false, bool includeSource = false)
        {
            var session = getQueryEditorSessionId(projectId, scanId);

            return QueryEditor.GetQueryAsync(session, editorQueryId, includeMetadata, includeSource).Result;
        }

        public string CreateProjectQueryByEditorQuery(Guid projectId, Guid scanId, string editorQueryId, string name, string path, long cwe, string language, string group, string severity, bool executable, long description, long sastId, List<string> presets, string source)
        {
            var session = getQueryEditorSessionId(projectId, scanId);

            CreateQueryRequest createBody = new CreateQueryRequest()
            {
                Name = name,
                Cwe = cwe,
                Language = language,
                Group = group,
                Severity = severity,
                Executable = executable,
                Description = description,

                Id = editorQueryId,
                Level = "project",
                Path = path,
                Presets = presets,
                SastId = sastId,

                Source = source
            };

            var createQueryResult = QueryEditor.CreateQueryAsync(createBody, session).Result;

            bool completed = false;
            string id = null;
            while (!completed)
            {
                System.Threading.Thread.Sleep(5 * 1000);

                var status = QueryEditor.CheckRequestStatusAsync(session, createQueryResult.Id).Result;

                if (status.Completed)
                {
                    completed = true;
                    if (status.Status == RequestStatusStatus.Finished)
                        id = status.Value?.Id;
                    else
                        throw new Exception($"Error creating query for project {projectId} with status \"{status.Status.ToString()}\". Message: \"{status.Value.Message}\"");
                }
            }

            if (string.IsNullOrWhiteSpace(id))
                throw new Exception($"Unknown error creating query for project {projectId}");

            return id;
        }

        public bool DeleteProjectQueryByEditorQuery(Guid projectId, Guid scanId, string editorQueryId)
        {
            var session = getQueryEditorSessionId(projectId, scanId);

            var deleteQueryResult = QueryEditor.DeleteQueryAsync(session, editorQueryId).Result;

            bool completed = false;
            while (!completed)
            {
                System.Threading.Thread.Sleep(5 * 1000);

                var status = QueryEditor.CheckRequestStatusAsync(session, deleteQueryResult.Id).Result;

                if (status.Completed)
                {
                    completed = true;
                    if (status.Status != RequestStatusStatus.Finished)
                        throw new Exception($"Error deleting query for project {projectId} with status \"{status.Status.ToString()}\". Message: \"{status.Value.Message}\"");
                }
            }

            return true;
        }

        #endregion

        #endregion

        #region GraphQL

        public SCALegalRisks GetSCAScanLegalRisk(Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            var query = @"
                        query ($scanId: UUID!, $where: LegalRiskModelFilterInput) {
                            legalRisksByScanId(scanId: $scanId, where: $where) {
                                totalCount
                                risksLevelCounts {
                                    critical
                                    high
                                    medium
                                    low
                                    none
                                    empty
                                }
                            }
                        }";

            // Define variables for the query
            var variables = new
            {
                scanId = scanId
            };

            return GraphQLClient.GetSCAScanLegalRisks(query, variables);
        }

        #endregion

        #region Logs

        const string MULTI_LANGUAGE_MODE = "MULTI_LANGUAGE_MODE";

        public int GetSASTEngineLanguageMode(Guid scanId)
        {
            string log = GetScanLog(scanId, SAST_Engine);
            foreach (var item in log.Split("\n"))
            {
                if (item.Contains($"{MULTI_LANGUAGE_MODE}="))
                    return int.Parse(item.Replace($"{MULTI_LANGUAGE_MODE}=", ""));
            }

            throw new NotSupportedException($"{MULTI_LANGUAGE_MODE} not found");
        }

        public string GetSASTScanLog(Guid scanId)
        {
            return GetScanLogs(scanId, SAST_Engine).Result;
        }

        public string GetScanLog(Guid scanId, string engine)
        {
            return GetScanLogs(scanId, engine).Result;
        }

        private async Task<string> GetScanLogs(Guid scanId, string engine)
        {
            if (string.IsNullOrEmpty(engine))
                throw new ArgumentNullException(nameof(engine));

            string token = authenticate();
            string serverRestEndpoint = $"{ASTServer.AbsoluteUri}api/logs/{scanId}/{engine}";

            using (var handler = new HttpClientHandler { AllowAutoRedirect = false })
            using (var client = new HttpClient(handler))
            {
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                using (var requestMessage = new HttpRequestMessage(HttpMethod.Get, serverRestEndpoint))
                {
                    var response = await _retryPolicy.ExecuteAsync(() => client.SendAsync(CloneHttpRequestMessage(requestMessage), HttpCompletionOption.ResponseHeadersRead)).ConfigureAwait(false);

                    try
                    {
                        if (response.StatusCode == HttpStatusCode.TemporaryRedirect || response.StatusCode == HttpStatusCode.Redirect)
                        {
                            string redirectUrl = response.Headers.Location?.ToString();
                            if (!string.IsNullOrEmpty(redirectUrl))
                            {
                                var redirectRequest = new HttpRequestMessage(HttpMethod.Get, redirectUrl);

                                var redirectResponse = await _retryPolicy.ExecuteAsync(() => client.SendAsync(CloneHttpRequestMessage(redirectRequest), HttpCompletionOption.ResponseHeadersRead)).ConfigureAwait(false);

                                try
                                {
                                    return redirectResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                                }
                                finally
                                {
                                    redirectResponse.Dispose();
                                }
                            }
                        }

                        return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    }
                    finally
                    {
                        response.Dispose();
                    }
                }
            }
        }

        /// <summary>
        /// Get the last note of the history of comments of the SAST finding.
        /// </summary>
        /// <param name="similarityID"></param>
        /// <param name="projects_ids"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public string GetLastSASTNote(string similarityID, params Guid[] projects_ids)
        {
            if (!projects_ids.Any())
                throw new ArgumentOutOfRangeException(nameof(projects_ids));

            var lastState = SASTResultsPredicates.GetLatestPredicatesBySimilarityIDAsync(similarityID, projects_ids).Result;
            return lastState.LatestPredicatePerProject?.FirstOrDefault()?.Comment;
        }

        private void loadSASTMetadataInfoForScans(params Guid[] projects_ids)
        {
            var scansToRequest = projects_ids.Where(x => !_sastScansMetada.ContainsKey(x));

            if (scansToRequest.Any())
            {
                foreach (var array in SplitArray<Guid>(scansToRequest.ToArray(), 50))
                {
                    var results = SASTMetadata.GetMetadataFromMultipleScansAsync(array).Result;
                    if (results.Scans != null)
                    {
                        foreach (var item in results.Scans)
                            _sastScansMetada.Add(item.ScanId, item);
                    }

                    if (results.Missing != null)
                    {
                        foreach (var item in results.Missing)
                            _sastScansMetada.Add(item, null);
                    }
                }
            }
        }

        public static IEnumerable<T[]> SplitArray<T>(T[] array, int chunkSize)
        {
            for (int i = 0; i < array.Length; i += chunkSize)
            {
                yield return array.Skip(i).Take(chunkSize).ToArray();
            }
        }

        public ScanInfo GetSASTScanInfo(Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            loadSASTMetadataInfoForScans(scanId);

            return _sastScansMetada[scanId];
        }

        public bool IsScanIncremental(Guid scanId)
        {
            var sastMetadata = GetSASTScanInfo(scanId);

            if (sastMetadata == null)
                return false;

            return sastMetadata.IsIncremental && !sastMetadata.IsIncrementalCanceled;
        }


        private IDictionary<Guid, Group> _groups = null;
        public IDictionary<Guid, Group> Groups
        {
            get
            {
                if (_groups == null)
                {
                    _groups = AccessManagement.GetGroupsAsync().Result.ToDictionary(x => x.Id);
                }

                return _groups;
            }
        }

        private IDictionary<Guid, User> _users = null;
        public IDictionary<Guid, User> Users
        {
            get
            {
                if (_users == null)
                {
                    _users = AccessManagement.GetUsersAsync().Result.ToDictionary(x => x.Id);
                }

                return _users;
            }
        }

        #endregion

        private bool _disposed = false;
        public void Dispose()
        {
            if (!_disposed)
            {
                endQueryEditorSessions();
                _disposed = true;
            }
        }
    }
}
