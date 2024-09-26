﻿//----------------------
// <auto-generated>
//     Generated using the NSwag toolchain v13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0)) (http://NSwag.org)
// </auto-generated>
//----------------------

#pragma warning disable 108 // Disable "CS0108 '{derivedDto}.ToJson()' hides inherited member '{dtoBase}.ToJson()'. Use the new keyword if hiding was intended."
#pragma warning disable 114 // Disable "CS0114 '{derivedDto}.RaisePropertyChanged(String)' hides inherited member 'dtoBase.RaisePropertyChanged(String)'. To make the current member override that implementation, add the override keyword. Otherwise add the new keyword."
#pragma warning disable 472 // Disable "CS0472 The result of the expression is always 'false' since a value of type 'Int32' is never equal to 'null' of type 'Int32?'
#pragma warning disable 1573 // Disable "CS1573 Parameter '...' has no matching param tag in the XML comment for ...
#pragma warning disable 1591 // Disable "CS1591 Missing XML comment for publicly visible type or member ..."
#pragma warning disable 8073 // Disable "CS8073 The result of the expression is always 'false' since a value of type 'T' is never equal to 'null' of type 'T?'"
#pragma warning disable 3016 // Disable "CS3016 Arrays as attribute arguments is not CLS-compliant"
#pragma warning disable 8603 // Disable "CS8603 Possible null reference return"

namespace Checkmarx.API.AST.Services.KicsResults
{
    using Checkmarx.API.AST.Services.SASTResults;
    using System;
    using System.Net.Http;
    using System = global::System;
    using static Checkmarx.API.AST.ASTClient;

    [System.CodeDom.Compiler.GeneratedCode("NSwag", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public partial class KicsResults
    {
        private string _baseUrl = "";
        private System.Net.Http.HttpClient _httpClient;
        private System.Lazy<Newtonsoft.Json.JsonSerializerSettings> _settings;

        public KicsResults(string baseUrl, System.Net.Http.HttpClient httpClient)
        {
            BaseUrl = baseUrl;
            _httpClient = httpClient;
            _settings = new System.Lazy<Newtonsoft.Json.JsonSerializerSettings>(CreateSerializerSettings);
        }

        private Newtonsoft.Json.JsonSerializerSettings CreateSerializerSettings()
        {
            var settings = new Newtonsoft.Json.JsonSerializerSettings();
            UpdateJsonSerializerSettings(settings);
            return settings;
        }

        public string BaseUrl
        {
            get { return _baseUrl; }
            set { _baseUrl = value; }
        }

        protected Newtonsoft.Json.JsonSerializerSettings JsonSerializerSettings { get { return _settings.Value; } }

        partial void UpdateJsonSerializerSettings(Newtonsoft.Json.JsonSerializerSettings settings);

        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, string url);
        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, System.Text.StringBuilder urlBuilder);
        partial void ProcessResponse(System.Net.Http.HttpClient client, System.Net.Http.HttpResponseMessage response);

        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        /// <summary>
        /// get KICS results by Scan ID, this is paginated API, use the ASTClient.GetKicsScanResultsById to get all of them.
        /// </summary>
        /// <param name="authorization">REQUIRED: JWT authorization token</param>
        /// <param name="accept">API version should be appended to this header</param>
        /// <param name="correlationId">correlation id to keep track of a flow if many APIs are involved</param>
        /// <param name="scan_id">filter by scan id</param>
        /// <param name="severity">filter by severity. OR operator between the items.</param>
        /// <param name="status">filter by status. OR operator between the items.</param>
        /// <param name="source_file">filter by source file name.</param>
        /// <param name="apply_predicates">if true will apply changes from predicates, otherwise will return the raw result.</param>
        /// <param name="offset">The number of items to skip before starting to collect the result set.</param>
        /// <param name="limit">The number of items to return.</param>
        /// <param name="sort">sorting ORDERED array. each string pattern "[-+]field". - mean ASC, + mean DESC.</param>
        /// <returns>successful operation</returns>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual async System.Threading.Tasks.Task<Response> GetKICSResultsByScanAsync(Guid scan_id, int? offset = null, int? limit = null, string authorization = null, string accept = null, System.Guid? correlationId = null,  System.Collections.Generic.IEnumerable<SeverityEnum> severity = null, System.Collections.Generic.IEnumerable<StatusEnum> status = null, string source_file = null, bool? apply_predicates = null,  System.Collections.Generic.IEnumerable<Anonymous> sort = null, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            if (scan_id == null)
                throw new System.ArgumentNullException("scan_id");

            var urlBuilder_ = new System.Text.StringBuilder();
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/?");
            urlBuilder_.Append(System.Uri.EscapeDataString("scan-id") + "=").Append(System.Uri.EscapeDataString(ConvertToString(scan_id, System.Globalization.CultureInfo.InvariantCulture))).Append("&");
            if (severity != null)
            {
                foreach (var item_ in severity) { urlBuilder_.Append(System.Uri.EscapeDataString("severity") + "=").Append(System.Uri.EscapeDataString(ConvertToString(item_, System.Globalization.CultureInfo.InvariantCulture))).Append("&"); }
            }
            if (status != null)
            {
                foreach (var item_ in status) { urlBuilder_.Append(System.Uri.EscapeDataString("status") + "=").Append(System.Uri.EscapeDataString(ConvertToString(item_, System.Globalization.CultureInfo.InvariantCulture))).Append("&"); }
            }
            if (source_file != null)
            {
                urlBuilder_.Append(System.Uri.EscapeDataString("source-file") + "=").Append(System.Uri.EscapeDataString(ConvertToString(source_file, System.Globalization.CultureInfo.InvariantCulture))).Append("&");
            }
            if (apply_predicates != null)
            {
                urlBuilder_.Append(System.Uri.EscapeDataString("apply-predicates") + "=").Append(System.Uri.EscapeDataString(ConvertToString(apply_predicates, System.Globalization.CultureInfo.InvariantCulture))).Append("&");
            }
            if (offset != null)
            {
                urlBuilder_.Append(System.Uri.EscapeDataString("offset") + "=").Append(System.Uri.EscapeDataString(ConvertToString(offset, System.Globalization.CultureInfo.InvariantCulture))).Append("&");
            }
            if (limit != null)
            {
                urlBuilder_.Append(System.Uri.EscapeDataString("limit") + "=").Append(System.Uri.EscapeDataString(ConvertToString(limit, System.Globalization.CultureInfo.InvariantCulture))).Append("&");
            }
            if (sort != null)
            {
                foreach (var item_ in sort) { urlBuilder_.Append(System.Uri.EscapeDataString("sort") + "=").Append(System.Uri.EscapeDataString(ConvertToString(item_, System.Globalization.CultureInfo.InvariantCulture))).Append("&"); }
            }
            urlBuilder_.Length--;

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {

                    if (authorization != null)
                        request_.Headers.TryAddWithoutValidation("Authorization", ConvertToString(authorization, System.Globalization.CultureInfo.InvariantCulture));

                    if (accept != null)
                        request_.Headers.TryAddWithoutValidation("Accept", ConvertToString(accept, System.Globalization.CultureInfo.InvariantCulture));

                    if (correlationId != null)
                        request_.Headers.TryAddWithoutValidation("CorrelationId", ConvertToString(correlationId, System.Globalization.CultureInfo.InvariantCulture));
                    request_.Method = new System.Net.Http.HttpMethod("GET");

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
                            var objectResponse_ = await ReadObjectResponseAsync<Response>(response_, headers_, cancellationToken).ConfigureAwait(false);
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
                return new ObjectResponseResult<T>(default(T), string.Empty);
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
            else if (value.GetType().IsArray)
            {
                var array = System.Linq.Enumerable.OfType<object>((System.Array)value);
                return string.Join(",", System.Linq.Enumerable.Select(array, o => ConvertToString(o, cultureInfo)));
            }

            var result = System.Convert.ToString(value, cultureInfo);
            return result == null ? "" : result;
        }
    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public partial class KicsResult
    {
        /// <summary>
        /// ID of the result
        /// </summary>
        [Newtonsoft.Json.JsonProperty("ID", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string ID { get; set; }

        /// <summary>
        /// ID of the Similarity feature (Indicator to identify a result by its first and last nodes)
        /// </summary>
        [Newtonsoft.Json.JsonProperty("similarityID", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string SimilarityID { get; set; }

        [Newtonsoft.Json.JsonProperty("severity", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public SeverityEnum Severity { get; set; }

        /// <summary>
        /// ID of the first scan id by resultHash
        /// </summary>
        [Newtonsoft.Json.JsonProperty("firstScanID", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public Guid FirstScanID { get; set; }

        /// <summary>
        /// date of the first found by resultHash
        /// </summary>
        [Newtonsoft.Json.JsonProperty("firstFoundAt", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        [Newtonsoft.Json.JsonConverter(typeof(DateFormatConverter))]
        public System.DateTimeOffset FirstFoundAt { get; set; }

        /// <summary>
        /// Creation date of the result
        /// </summary>
        [Newtonsoft.Json.JsonProperty("foundAt", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        [Newtonsoft.Json.JsonConverter(typeof(DateFormatConverter))]
        public System.DateTimeOffset FoundAt { get; set; }

        [Newtonsoft.Json.JsonProperty("status", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public StatusEnum Status { get; set; }

        [Newtonsoft.Json.JsonProperty("type", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Type { get; set; } = "infrastructure";

        /// <summary>
        /// Query ID
        /// </summary>
        [Newtonsoft.Json.JsonProperty("queryID", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string QueryID { get; set; }

        /// <summary>
        /// Query name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("queryName", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string QueryName { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("group", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Group { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("queryUrl", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Uri QueryUrl { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("fileName", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string FileName { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("line", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public int Line { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("platform", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Platform { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("issueType", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string IssueType { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("searchKey", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string SearchKey { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("searchValue", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public int SearchValue { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("expectedValue", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string ExpectedValue { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("actualValue", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string ActualValue { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("value", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Value { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("description", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Description { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("comments", Required = Newtonsoft.Json.Required.AllowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Include)]
        public string Comments { get; set; }

        /// <summary>
        /// Query group name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("category", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Category { get; set; }

        /// <summary>
        /// Resource name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("resourceName", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string ResourceName { get; set; }

        /// <summary>
        /// state enum of a result.
        /// </summary>
        [Newtonsoft.Json.JsonProperty("state", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public KicsStateEnum State { get; set; }

        /// <summary>
        /// Resource type
        /// </summary>
        [Newtonsoft.Json.JsonProperty("resourceType", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string ResourceType { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties = new System.Collections.Generic.Dictionary<string, object>();

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties; }
            set { _additionalProperties = value; }
        }

    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.15.10.0 (NJsonSchema v10.6.10.0 (Newtonsoft.Json v11.0.0.0))")]
    public enum KicsStateEnum
    {

        [System.Runtime.Serialization.EnumMember(Value = @"TO_VERIFY")]
        TO_VERIFY = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"NOT_EXPLOITABLE")]
        NOT_EXPLOITABLE = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"PROPOSED_NOT_EXPLOITABLE")]
        PROPOSED_NOT_EXPLOITABLE = 2,

        [System.Runtime.Serialization.EnumMember(Value = @"CONFIRMED")]
        CONFIRMED = 3,

        [System.Runtime.Serialization.EnumMember(Value = @"URGENT")]
        URGENT = 4,

    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public partial class ResultNode
    {
        /// <summary>
        /// Column position of the node
        /// </summary>
        [Newtonsoft.Json.JsonProperty("column", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public int Column { get; set; }

        /// <summary>
        /// Full file name of the containing source file
        /// </summary>
        [Newtonsoft.Json.JsonProperty("fileName", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string FileName { get; set; }

        /// <summary>
        /// FQN of the node
        /// </summary>
        [Newtonsoft.Json.JsonProperty("fullName", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string FullName { get; set; }

        /// <summary>
        /// Length of the node
        /// </summary>
        [Newtonsoft.Json.JsonProperty("length", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public int Length { get; set; }

        /// <summary>
        /// Line position of the node
        /// </summary>
        [Newtonsoft.Json.JsonProperty("line", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public int Line { get; set; }

        /// <summary>
        /// Line position of the containing method
        /// </summary>
        [Newtonsoft.Json.JsonProperty("methodLine", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public int MethodLine { get; set; }

        /// <summary>
        /// node name
        /// </summary>
        [Newtonsoft.Json.JsonProperty("name", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Name { get; set; }

        /// <summary>
        /// node DomType
        /// </summary>
        [Newtonsoft.Json.JsonProperty("domType", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string DomType { get; set; }

        /// <summary>
        /// Please use "nodeHash" instead.
        /// </summary>
        [Newtonsoft.Json.JsonProperty("nodeSystemID", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        [System.Obsolete]
        public string NodeSystemID { get; set; }

        /// <summary>
        /// ID of the customer tenant
        /// </summary>
        [Newtonsoft.Json.JsonProperty("nodeHash", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string NodeHash { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties = new System.Collections.Generic.Dictionary<string, object>();

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties; }
            set { _additionalProperties = value; }
        }

    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public partial class WebError
    {
        [Newtonsoft.Json.JsonProperty("code", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public int Code { get; set; }

        [Newtonsoft.Json.JsonProperty("message", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public string Message { get; set; }

        [Newtonsoft.Json.JsonProperty("data", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public object Data { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties = new System.Collections.Generic.Dictionary<string, object>();

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties; }
            set { _additionalProperties = value; }
        }

    }

    /// <summary>
    /// Severity enum of a result.
    /// </summary>
    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public enum SeverityEnum
    {

        [System.Runtime.Serialization.EnumMember(Value = @"HIGH")]
        HIGH = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"MEDIUM")]
        MEDIUM = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"LOW")]
        LOW = 2,

        [System.Runtime.Serialization.EnumMember(Value = @"INFO")]
        INFO = 3,

    }

    /// <summary>
    /// Status enum of a result
    /// </summary>
    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public enum StatusEnum
    {

        [System.Runtime.Serialization.EnumMember(Value = @"NEW")]
        NEW = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"RECURRENT")]
        RECURRENT = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"FIXED")]
        FIXED = 2,

    }

    /// <summary>
    /// Operation type
    /// </summary>
    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public enum OperationEnum
    {

        [System.Runtime.Serialization.EnumMember(Value = @"CONTAINS")]
        CONTAINS = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"NOT_CONTAINS")]
        NOT_CONTAINS = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"EQUAL")]
        EQUAL = 2,

        [System.Runtime.Serialization.EnumMember(Value = @"NOT_EQUAL")]
        NOT_EQUAL = 3,

    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public enum Anonymous
    {

        [System.Runtime.Serialization.EnumMember(Value = @"-severity")]
        Minusseverity = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"+severity")]
        Plusseverity = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"-status")]
        Minusstatus = 2,

        [System.Runtime.Serialization.EnumMember(Value = @"+status")]
        Plusstatus = 3,

        [System.Runtime.Serialization.EnumMember(Value = @"-firstfoundat")]
        Minusfirstfoundat = 4,

        [System.Runtime.Serialization.EnumMember(Value = @"+firstfoundat")]
        Plusfirstfoundat = 5,

        [System.Runtime.Serialization.EnumMember(Value = @"-foundat")]
        Minusfoundat = 6,

        [System.Runtime.Serialization.EnumMember(Value = @"+foundat")]
        Plusfoundat = 7,

        [System.Runtime.Serialization.EnumMember(Value = @"firstscanid")]
        Firstscanid = 8,

        [System.Runtime.Serialization.EnumMember(Value = @"+firstscanid")]
        Plusfirstscanid = 9,

    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public partial class Response
    {
        [Newtonsoft.Json.JsonProperty("results", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<KicsResult> Results { get; set; }

        [Newtonsoft.Json.JsonProperty("totalCount", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public int TotalCount { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties = new System.Collections.Generic.Dictionary<string, object>();

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties; }
            set { _additionalProperties = value; }
        }

    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    internal class DateFormatConverter : Newtonsoft.Json.Converters.IsoDateTimeConverter
    {
        public DateFormatConverter()
        {
            DateTimeFormat = "yyyy-MM-dd";
        }
    }



    [System.CodeDom.Compiler.GeneratedCode("NSwag", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public partial class ApiException : System.Exception
    {
        public int StatusCode { get; private set; }

        public string Response { get; private set; }

        public System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IEnumerable<string>> Headers { get; private set; }

        public ApiException(string message, int statusCode, string response, System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IEnumerable<string>> headers, System.Exception innerException)
            : base(message + "\n\nStatus: " + statusCode + "\nResponse: \n" + ((response == null) ? "(null)" : response.Substring(0, response.Length >= 512 ? 512 : response.Length)), innerException)
        {
            StatusCode = statusCode;
            Response = response;
            Headers = headers;
        }

        public override string ToString()
        {
            return string.Format("HTTP Response: \n\n{0}\n\n{1}", Response, base.ToString());
        }
    }

    [System.CodeDom.Compiler.GeneratedCode("NSwag", "13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v12.0.0.0))")]
    public partial class ApiException<TResult> : ApiException
    {
        public TResult Result { get; private set; }

        public ApiException(string message, int statusCode, string response, System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IEnumerable<string>> headers, TResult result, System.Exception innerException)
            : base(message, statusCode, response, headers, innerException)
        {
            Result = result;
        }
    }

}

#pragma warning restore 1591
#pragma warning restore 1573
#pragma warning restore 472
#pragma warning restore 114
#pragma warning restore 108
#pragma warning restore 3016
#pragma warning restore 8603