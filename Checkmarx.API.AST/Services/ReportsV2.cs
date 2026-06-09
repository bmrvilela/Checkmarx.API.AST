#pragma warning disable 108
#pragma warning disable 114
#pragma warning disable 472
#pragma warning disable 612
#pragma warning disable 649
#pragma warning disable 1573
#pragma warning disable 1591
#pragma warning disable 8073
#pragma warning disable 3016
#pragma warning disable 8600
#pragma warning disable 8602
#pragma warning disable 8603
#pragma warning disable 8604
#pragma warning disable 8625

namespace Checkmarx.API.AST.Services.ReportsV2
{
    using Checkmarx.API.AST.Exceptions;
    using System;
    using System.Diagnostics;
    using static Checkmarx.API.AST.ASTClient;
    using System = global::System;

    public partial class ReportsV2
    {
#pragma warning disable 8618
        private string _baseUrl;
#pragma warning restore 8618

        private System.Net.Http.HttpClient _httpClient;
        private static System.Lazy<Newtonsoft.Json.JsonSerializerSettings> _settings = new System.Lazy<Newtonsoft.Json.JsonSerializerSettings>(CreateSerializerSettings, true);
        private Newtonsoft.Json.JsonSerializerSettings _instanceSettings;

#pragma warning disable CS8618
        public ReportsV2(System.Uri aSTServer, System.Net.Http.HttpClient httpClient)
        {
#pragma warning restore CS8618
            BaseUrl = $"{aSTServer.AbsoluteUri}api/reports/v2";
            _httpClient = httpClient;
            Initialize();
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

        protected Newtonsoft.Json.JsonSerializerSettings JsonSerializerSettings { get { return _instanceSettings ?? _settings.Value; } }

        static partial void UpdateJsonSerializerSettings(Newtonsoft.Json.JsonSerializerSettings settings);

        partial void Initialize();

        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, string url);
        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, System.Text.StringBuilder urlBuilder);
        partial void ProcessResponse(System.Net.Http.HttpClient client, System.Net.Http.HttpResponseMessage response);

        // ──────────────────────────────────────────────────────────
        // POST /  — Create a customized scan or project report
        // ──────────────────────────────────────────────────────────

        public virtual System.Threading.Tasks.Task<ReportV2CreateResponse> CreateScanReportAsync(CreateScanReportV2Request body)
        {
            return CreateScanReportAsync(body, System.Threading.CancellationToken.None);
        }

        public virtual async System.Threading.Tasks.Task<ReportV2CreateResponse> CreateScanReportAsync(CreateScanReportV2Request body, System.Threading.CancellationToken cancellationToken)
        {
            if (body == null)
                throw new System.ArgumentNullException("body");

            return await PostReportAsync(body, cancellationToken).ConfigureAwait(false);
        }

        public virtual System.Threading.Tasks.Task<ReportV2CreateResponse> CreateProjectReportAsync(CreateProjectReportV2Request body)
        {
            return CreateProjectReportAsync(body, System.Threading.CancellationToken.None);
        }

        public virtual async System.Threading.Tasks.Task<ReportV2CreateResponse> CreateProjectReportAsync(CreateProjectReportV2Request body, System.Threading.CancellationToken cancellationToken)
        {
            if (body == null)
                throw new System.ArgumentNullException("body");

            return await PostReportAsync(body, cancellationToken).ConfigureAwait(false);
        }

        private async System.Threading.Tasks.Task<ReportV2CreateResponse> PostReportAsync(object body, System.Threading.CancellationToken cancellationToken)
        {
            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    var json_ = Newtonsoft.Json.JsonConvert.SerializeObject(body, JsonSerializerSettings);
                    var content_ = new System.Net.Http.StringContent(json_);
                    content_.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json; version=2.0");
                    request_.Content = content_;
                    request_.Method = new System.Net.Http.HttpMethod("POST");
                    request_.Headers.Accept.Add(System.Net.Http.Headers.MediaTypeWithQualityHeaderValue.Parse("application/json"));

                    var urlBuilder_ = new System.Text.StringBuilder();
                    if (!string.IsNullOrEmpty(_baseUrl)) urlBuilder_.Append(_baseUrl.TrimEnd('/'));

                    PrepareRequest(client_, request_, urlBuilder_);
                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);
                    PrepareRequest(client_, request_, url_);

                    var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
                    var disposeResponse_ = true;
                    try
                    {
                        var headers_ = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.IEnumerable<string>>();
                        foreach (var item_ in response_.Headers)
                            headers_[item_.Key] = item_.Value;
                        if (response_.Content != null && response_.Content.Headers != null)
                            foreach (var item_ in response_.Content.Headers)
                                headers_[item_.Key] = item_.Value;

                        ProcessResponse(client_, response_);

                        var status_ = (int)response_.StatusCode;

#if DEBUG
                        var content = await response_.Content.ReadAsStringAsync();
                        Trace.WriteLine(content);
#endif

                        if (status_ == 202)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<ReportV2CreateResponse>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            return objectResponse_.Object;
                        }
                        else if (status_ == 400)
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("Bad Request", status_, responseData_, headers_, null);
                        }
                        else if (status_ == 401)
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("Unauthorized", status_, responseData_, headers_, null);
                        }
                        else if (status_ == 403)
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("Forbidden", status_, responseData_, headers_, null);
                        }
                        else
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("The HTTP status code of the response was not expected (" + status_ + ").", status_, responseData_, headers_, null);
                        }
                    }
                    finally
                    {
                        if (disposeResponse_) response_.Dispose();
                    }
                }
            }
            finally
            {
                if (disposeClient_) client_.Dispose();
            }
        }

        // ──────────────────────────────────────────────────────────
        // ReadObjectResponseAsync / ConvertToString helpers
        // ──────────────────────────────────────────────────────────

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
                return new ObjectResponseResult<T>(default(T), string.Empty);

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
                return "";

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
                            return attribute.Value != null ? attribute.Value : name;
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
                    valueTextArray[i] = ConvertToString(valueArray.GetValue(i), cultureInfo);
                return string.Join(",", valueTextArray);
            }

            var result = System.Convert.ToString(value, cultureInfo);
            return result == null ? "" : result;
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Request Models
    // ──────────────────────────────────────────────────────────────

    public partial class CreateScanReportV2Request
    {
        [Newtonsoft.Json.JsonProperty("reportName", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required(AllowEmptyStrings = true)]
        public string ReportName { get; set; } = "improved-scan-report";

        [Newtonsoft.Json.JsonProperty("reportType", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required(AllowEmptyStrings = true)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public ReportV2Type ReportType { get; set; }

        [Newtonsoft.Json.JsonProperty("fileFormat", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required(AllowEmptyStrings = true)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public ScanReportV2FileFormat FileFormat { get; set; }

        [Newtonsoft.Json.JsonProperty("reportFilename", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string ReportFilename { get; set; }

        [Newtonsoft.Json.JsonProperty("timezone", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Timezone { get; set; }

        [Newtonsoft.Json.JsonProperty("sections", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> Sections { get; set; }

        [Newtonsoft.Json.JsonProperty("emails", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> Emails { get; set; }

        [Newtonsoft.Json.JsonProperty("entities", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required]
        public System.Collections.Generic.ICollection<ReportV2Entity> Entities { get; set; } = new System.Collections.ObjectModel.Collection<ReportV2Entity>();

        [Newtonsoft.Json.JsonProperty("filters", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public ReportV2Filters Filters { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }
    }

    public partial class CreateProjectReportV2Request
    {
        [Newtonsoft.Json.JsonProperty("reportName", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required(AllowEmptyStrings = true)]
        public string ReportName { get; set; } = "improved-project-report";

        [Newtonsoft.Json.JsonProperty("reportType", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required(AllowEmptyStrings = true)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public ReportV2Type ReportType { get; set; }

        [Newtonsoft.Json.JsonProperty("fileFormat", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required(AllowEmptyStrings = true)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public ProjectReportV2FileFormat FileFormat { get; set; }

        [Newtonsoft.Json.JsonProperty("reportFilename", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string ReportFilename { get; set; }

        [Newtonsoft.Json.JsonProperty("timezone", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Timezone { get; set; }

        [Newtonsoft.Json.JsonProperty("sections", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> Sections { get; set; }

        [Newtonsoft.Json.JsonProperty("emails", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> Emails { get; set; }

        [Newtonsoft.Json.JsonProperty("entities", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required]
        public System.Collections.Generic.ICollection<ReportV2Entity> Entities { get; set; } = new System.Collections.ObjectModel.Collection<ReportV2Entity>();

        [Newtonsoft.Json.JsonProperty("filters", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public ReportV2Filters Filters { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }
    }

    public partial class ReportV2Entity
    {
        [Newtonsoft.Json.JsonProperty("entity", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required(AllowEmptyStrings = true)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public ReportV2EntityType Entity { get; set; }

        [Newtonsoft.Json.JsonProperty("ids", Required = Newtonsoft.Json.Required.Always)]
        [System.ComponentModel.DataAnnotations.Required]
        public System.Collections.Generic.ICollection<Guid> Ids { get; set; } = new System.Collections.ObjectModel.Collection<Guid>();

        [Newtonsoft.Json.JsonProperty("tags", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> Tags { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }
    }

    public partial class ReportV2Filters
    {
        [Newtonsoft.Json.JsonProperty("scanners", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> Scanners { get; set; }

        [Newtonsoft.Json.JsonProperty("hidePrivatePackages", Required = Newtonsoft.Json.Required.AllowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Boolean HidePrivatePackages { get; set; } = default(Boolean);

        [Newtonsoft.Json.JsonProperty("severities", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> Severities { get; set; }

        [Newtonsoft.Json.JsonProperty("states", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> States { get; set; }

        [Newtonsoft.Json.JsonProperty("status", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<string> Status { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Response Models
    // ──────────────────────────────────────────────────────────────

    public partial class ReportV2CreateResponse
    {
        [Newtonsoft.Json.JsonProperty("reportId", Required = Newtonsoft.Json.Required.Default, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Guid ReportId { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Enums
    // ──────────────────────────────────────────────────────────────

    public enum ReportV2Type
    {
        [System.Runtime.Serialization.EnumMember(Value = @"cli")]
        Cli = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"ui")]
        Ui = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"email")]
        Email = 2,
    }

    public enum ScanReportV2FileFormat
    {
        [System.Runtime.Serialization.EnumMember(Value = @"pdf")]
        Pdf = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"json")]
        Json = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"csv")]
        Csv = 2,
    }

    public enum ProjectReportV2FileFormat
    {
        [System.Runtime.Serialization.EnumMember(Value = @"pdf")]
        Pdf = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"json")]
        Json = 1,
    }

    public enum ReportV2EntityType
    {
        [System.Runtime.Serialization.EnumMember(Value = @"scan")]
        Scan = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"project")]
        Project = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"application")]
        Application = 2,
    }

    public static class ReportV2Sections
    {
        // Scan report sections
        public const string ScanInformation = "scan-information";
        public const string ResultsOverview = "results-overview";
        public const string ScanResults = "scan-results";
        public const string ResolvedResults = "resolved-results";
        public const string Categories = "categories";
        public const string VulnerabilityDetails = "vulnerability-details";

        // Project report sections
        public const string ProjectsOverview = "projects-overview";
        public const string TotalVulnerabilitiesOverview = "total-vulnerabilities-overview";
        public const string VulnerabilitiesInsights = "vulnerabilities-insights";
    }
}

#pragma warning restore  108
#pragma warning restore  114
#pragma warning restore  472
#pragma warning restore  612
#pragma warning restore  649
#pragma warning restore 1573
#pragma warning restore 1591
#pragma warning restore 8073
#pragma warning restore 3016
#pragma warning restore 8600
#pragma warning restore 8602
#pragma warning restore 8603
#pragma warning restore 8604
#pragma warning restore 8625
