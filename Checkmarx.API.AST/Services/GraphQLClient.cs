using Checkmarx.API.AST.Exceptions;
using Checkmarx.API.AST.Services.SASTQueriesAudit;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using static Checkmarx.API.AST.ASTClient;

namespace Checkmarx.API.AST.Services
{
    public partial class GraphQLClient
    {
#pragma warning disable 8618
        private string _baseUrl;
#pragma warning restore 8618

        private static System.Lazy<Newtonsoft.Json.JsonSerializerSettings> _settings = new System.Lazy<Newtonsoft.Json.JsonSerializerSettings>(CreateSerializerSettings, true);

        private readonly HttpClient _httpClient;

        public GraphQLClient(string endpointUri, HttpClient httpClient)
        {
            if (string.IsNullOrWhiteSpace(endpointUri))
                throw new ArgumentException("Endpoint URI cannot be null or empty", nameof(endpointUri));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            BaseUrl = endpointUri;
        }


        private static Newtonsoft.Json.JsonSerializerSettings CreateSerializerSettings()
        {
            var settings = new Newtonsoft.Json.JsonSerializerSettings();
            UpdateJsonSerializerSettings(settings);
            return settings;
        }

        public string BaseUrl
        {
            get { return _baseUrl; }
            set
            {
                _baseUrl = value;
                if (!string.IsNullOrEmpty(_baseUrl) && !_baseUrl.EndsWith("/"))
                    _baseUrl += '/';
            }
        }

        protected Newtonsoft.Json.JsonSerializerSettings JsonSerializerSettings { get { return _settings.Value; } }

        static partial void UpdateJsonSerializerSettings(Newtonsoft.Json.JsonSerializerSettings settings);

        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, string url);
        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, System.Text.StringBuilder urlBuilder);
        partial void ProcessResponse(System.Net.Http.HttpClient client, System.Net.Http.HttpResponseMessage response);


        public async Task<string> ExecuteQueryAsync(string query, object variables = null)
        {
            if (string.IsNullOrWhiteSpace(query))
                throw new ArgumentException("Query cannot be null or empty", nameof(query));

            var requestBody = new
            {
                query,
                variables
            };

            var jsonContent = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(requestBody),
                Encoding.UTF8,
                "application/json"
            );

            var response = await _retryPolicy.ExecuteAsync(() => _httpClient.PostAsync(BaseUrl, jsonContent)).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"Request failed with status code {response.StatusCode}: {errorContent}");
            }

            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> GetFindingsChangeHistoryAsync(Guid projectId, Guid scanId, string packageName, string packageVersion,
            string packageManager, string vulnerabilityId)
        {
            string findingChangeHistory = $"{{    \"query\": \"query ($scanId: UUID!, $projectId: String, $isLatest: Boolean!, $packageName: String, $packageVersion: String, $packageManager: String, $vulnerabilityId: String) {{ searchPackageVulnerabilityStateAndScoreActions (scanId: $scanId, projectId: $projectId, isLatest: $isLatest, packageName: $packageName, packageVersion: $packageVersion, packageManager: $packageManager, vulnerabilityId: $vulnerabilityId) {{ actions {{ isComment, actionType, actionValue, enabled, createdAt, previousActionValue, comment {{ id, message, createdOn, userName }} }} }} }}\",    \"variables\": {{        \"scanId\": \"{scanId}\",        \"projectId\": \"{projectId}\",        \"isLatest\": true,        \"packageName\": \"{packageName}\",        \"packageVersion\": \"{packageVersion}\",        \"packageManager\": \"{packageManager}\",        \"vulnerabilityId\": \"{vulnerabilityId}\"    }}}}";

            var jsonContent = new StringContent(
                findingChangeHistory,
                Encoding.UTF8,
                "application/json"
            );

            var response = await _retryPolicy.ExecuteAsync(() => _httpClient.PostAsync(BaseUrl, jsonContent)).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"Request failed with status code {response.StatusCode}: {errorContent}");
            }

            return await response.Content.ReadAsStringAsync();
        }


        public ICollection<ReportingPackage> GetSCAProjectsThanContainLibraryAsync(string packageName, IEnumerable<string> packageVersions, System.Threading.CancellationToken cancellationToken = default)
        {
           List<ReportingPackage> cveProjects = new List<ReportingPackage>();

            foreach (var versionsChunk in packageVersions.Chunk(1000))
            {
                cveProjects.AddRange(getSCAProjectsThanContainLibraryAsync(packageName, versionsChunk, cancellationToken).Result.Data.ReportingPackages);
            }

            return cveProjects;
        }


        private async Task<CveProjects> getSCAProjectsThanContainLibraryAsync(string packageName, IEnumerable<string> packageVersions, System.Threading.CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(packageName))
                throw new ArgumentException("Library name cannot be null or empty", nameof(packageName));

            var urlBuilder_ = new System.Text.StringBuilder();
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "");

            StringBuilder whereClause = new StringBuilder();

            whereClause.Append($" {{ \"and\": [ {{ \"packageName\": {{ \"eq\": \"{packageName}\" }}  }},                {{                     \"or\": [ {string.Join(",", packageVersions.Select(x => $"{{ \"packageVersion\":  {{ \"eq\":  \"{x}\" }}  }}"))} ]                }} ]                }}");

            string queryForProject = $"{{    \"query\": \"query ($where: ReportingPackageModelFilterInput, $take: Int!, $skip: Int!, $order: [ReportingPackageModelSortInput!], $searchTerm: String) {{ reportingPackages (where: $where, take: $take, skip: $skip, order: $order, searchTerm: $searchTerm) {{ projectId, projectName, packageName, packageVersion, scanId }} }}\",    \"variables\": {{        \"where\": { whereClause.ToString() },        \"take\": 1000,        \"skip\": 0,        \"order\": [            {{                \"isMalicious\": \"DESC\"            }}        ]    }}}}";

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    var content_ = new System.Net.Http.StringContent(queryForProject);
                    content_.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
                    request_.Content = content_;

                    request_.Method = new System.Net.Http.HttpMethod("POST");

                    PrepareRequest(client_, request_, urlBuilder_);

                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url_);

                    var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
                    var disposeResponse_ = true;
                    try
                    {
                        var headers_ = System.Linq.Enumerable.ToDictionary(response_.Headers, h_ => h_.Key, h_ => h_.Value);
                        if (response_.Content != null && response_.Content.Headers != null)
                        {
                            foreach (var item_ in response_.Content.Headers)
                                headers_[item_.Key] = item_.Value;
                        }

                        ProcessResponse(client_, response_);

                        var status_ = (int)response_.StatusCode;
                        if (status_ == 200)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<CveProjects>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            return objectResponse_.Object;
                        }
                        else
                        if (status_ == 400)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<WebError>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            throw new ApiException<WebError>("Invalid request supplied.", status_, objectResponse_.Text, headers_, objectResponse_.Object, null);
                        }
                        else
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("The HTTP status code of the response was not expected (" + status_ + ").", status_, responseData_, headers_, null);
                        }
                    }
                    finally
                    {
                        if (disposeResponse_)
                            response_.Dispose();
                    }
                }
            }
            finally
            {
                if (disposeClient_)
                    client_.Dispose();
            }
        }

        public SCALegalRisks GetSCAScanLegalRisks(string query, object variables = null)
        {
            var response = ExecuteQueryAsync(query, variables).GetAwaiter().GetResult();
            return System.Text.Json.JsonSerializer.Deserialize<SCALegalRisks>(
                response,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

        protected struct ObjectResponseResult<T>
        {
            public ObjectResponseResult(T responseObject, string responseText)
            {
                this.Object = responseObject;
                this.Text = responseText;
            }

            public T Object { get; }

            public string Text { get; }
        }

        public bool ReadResponseAsString { get; set; }

        protected virtual async System.Threading.Tasks.Task<ObjectResponseResult<T>> ReadObjectResponseAsync<T>(System.Net.Http.HttpResponseMessage response, System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IEnumerable<string>> headers, System.Threading.CancellationToken cancellationToken)
        {
            if (response == null || response.Content == null)
            {
                return new ObjectResponseResult<T>(default, string.Empty);
            }

            if (ReadResponseAsString)
            {
                var responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                try
                {
                    var typedBody = Newtonsoft.Json.JsonConvert.DeserializeObject<T>(responseText, JsonSerializerSettings);
                    return new ObjectResponseResult<T>(typedBody, responseText);
                }
                catch (Newtonsoft.Json.JsonException exception)
                {
                    var message = "Could not deserialize the response body string as " + typeof(T).FullName + ".";
                    throw new ApiException(message, (int)response.StatusCode, responseText, headers, exception);
                }
            }
            else
            {
                try
                {
                    using (var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                    using (var streamReader = new System.IO.StreamReader(responseStream))
                    using (var jsonTextReader = new Newtonsoft.Json.JsonTextReader(streamReader))
                    {
                        var serializer = Newtonsoft.Json.JsonSerializer.Create(JsonSerializerSettings);
                        var typedBody = serializer.Deserialize<T>(jsonTextReader);
                        return new ObjectResponseResult<T>(typedBody, string.Empty);
                    }
                }
                catch (Newtonsoft.Json.JsonException exception)
                {
                    var message = "Could not deserialize the response body stream as " + typeof(T).FullName + ".";
                    throw new ApiException(message, (int)response.StatusCode, string.Empty, headers, exception);
                }
            }
        }

        private string ConvertToString(object value, System.Globalization.CultureInfo cultureInfo)
        {
            if (value == null)
            {
                return "";
            }

            if (value is System.Enum)
            {
                var name = System.Enum.GetName(value.GetType(), value);
                if (name != null)
                {
                    var field = System.Reflection.IntrospectionExtensions.GetTypeInfo(value.GetType()).GetDeclaredField(name);
                    if (field != null)
                    {
                        var attribute = System.Reflection.CustomAttributeExtensions.GetCustomAttribute(field, typeof(System.Runtime.Serialization.EnumMemberAttribute))
                            as System.Runtime.Serialization.EnumMemberAttribute;
                        if (attribute != null)
                        {
                            return attribute.Value != null ? attribute.Value : name;
                        }
                    }

                    var converted = System.Convert.ToString(System.Convert.ChangeType(value, System.Enum.GetUnderlyingType(value.GetType()), cultureInfo));
                    return converted == null ? string.Empty : converted;
                }
            }
            else if (value is bool)
            {
                return System.Convert.ToString((bool)value, cultureInfo).ToLowerInvariant();
            }
            else if (value is byte[])
            {
                return System.Convert.ToBase64String((byte[])value);
            }
            else if (value is string[])
            {
                return string.Join(",", (string[])value);
            }
            else if (value.GetType().IsArray)
            {
                var valueArray = (System.Array)value;
                var valueTextArray = new string[valueArray.Length];
                for (var i = 0; i < valueArray.Length; i++)
                {
                    valueTextArray[i] = ConvertToString(valueArray.GetValue(i), cultureInfo);
                }
                return string.Join(",", valueTextArray);
            }

            var result = System.Convert.ToString(value, cultureInfo);
            return result == null ? "" : result;
        }

    }



    public partial class CveProjects
    {
        [JsonProperty("data", NullValueHandling = NullValueHandling.Ignore)]
        public ReportingPackagesData Data { get; set; }
    }

    public partial class ReportingPackagesData
    {
        [JsonProperty("reportingPackages", NullValueHandling = NullValueHandling.Ignore)]
        public List<ReportingPackage> ReportingPackages { get; set; }
    }

    public partial class ReportingPackage
    {
        [JsonProperty("projectId", NullValueHandling = NullValueHandling.Ignore)]
        public Guid ProjectId { get; set; }

        [JsonProperty("projectName", NullValueHandling = NullValueHandling.Ignore)]
        public string ProjectName { get; set; }

        [JsonProperty("packageName", NullValueHandling = NullValueHandling.Ignore)]
        public string PackageName { get; set; }

        [JsonProperty("packageVersion", NullValueHandling = NullValueHandling.Ignore)]
        public string PackageVersion { get; set; }

        [JsonProperty("scanId", NullValueHandling = NullValueHandling.Ignore)]
        public Guid ScanId { get; set; }
    }

    #region LegalRisk

    public class SCALegalRisks
    {
        public SCALegalRisksData Data { get; set; }
    }

    public class SCALegalRisksData
    {
        public LegalRisksByScanId LegalRisksByScanId { get; set; }
    }

    public class LegalRisksByScanId
    {
        public int TotalCount { get; set; }
        public RisksLevelCounts RisksLevelCounts { get; set; }
    }

    public class RisksLevelCounts
    {
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int None { get; set; }
        public int Empty { get; set; }
    }

    #endregion


    // Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
    public class SCAAction
    {
        [JsonProperty("isComment")]
        public bool? IsComment { get; set; }

        [JsonProperty("actionType")]
        public string ActionType { get; set; }

        [JsonProperty("actionValue")]
        public string ActionValue { get; set; }

        [JsonProperty("enabled")]
        public bool? Enabled { get; set; }

        [JsonProperty("createdAt")]
        public DateTime? CreatedAt { get; set; }

        [JsonProperty("previousActionValue")]
        public string PreviousActionValue { get; set; }

        [JsonProperty("comment")]
        public Comment Comment { get; set; }
    }

    public class Comment
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("message")]
        public string Message { get; set; }

        [JsonProperty("createdOn")]
        public DateTime? CreatedOn { get; set; }

        [JsonProperty("userName")]
        public string UserName { get; set; }
    }

    public class Info
    {
        [JsonProperty("searchPackageVulnerabilityStateAndScoreActions")]
        public SearchPackageVulnerabilityStateAndScoreActions SearchPackageVulnerabilityStateAndScoreActions { get; set; }
    }

    public class SCAPredicateHistory
    {
        [JsonProperty("data")]
        public Info Data { get; set; }
    }

    public class SearchPackageVulnerabilityStateAndScoreActions
    {
        [JsonProperty("actions")]
        public List<SCAAction> Actions { get; set; }
    }


}
