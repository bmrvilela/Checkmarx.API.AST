namespace Checkmarx.API.AST.Services
{
    using System.Diagnostics;
    using System = global::System;
    using static Checkmarx.API.AST.ASTClient;
    using Checkmarx.API.AST.Exceptions;
    using Checkmarx.API.AST.Errors;

    /// <summary>
    /// Credits (AI actions such as triage and remediation) license, consumption and burn rate.
    /// </summary>
    public partial class Credits
    {
        private string _baseUrl;
        private System.Net.Http.HttpClient _httpClient;
        private static System.Lazy<Newtonsoft.Json.JsonSerializerSettings> _settings = new System.Lazy<Newtonsoft.Json.JsonSerializerSettings>(CreateSerializerSettings, true);

        public Credits(System.Uri aSTServer, System.Net.Http.HttpClient httpClient)
        {
            BaseUrl = $"{aSTServer.AbsoluteUri}api/credits";
            _httpClient = httpClient;
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

        /// <summary>
        /// Get the credits license status (trial/active/expired and its dates)
        /// </summary>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual System.Threading.Tasks.Task<CreditsLicenseStatus> GetLicenseStatusAsync(System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            return GetAsync<CreditsLicenseStatus>("license/status", null, cancellationToken);
        }

        /// <summary>
        /// Get the credits balance (available, used, total) and enforcement state
        /// </summary>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual System.Threading.Tasks.Task<CreditsInfo> GetInfoAsync(System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            return GetAsync<CreditsInfo>("info", null, cancellationToken);
        }

        /// <summary>
        /// Get the monthly burn rate and the estimated depletion date
        /// </summary>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual System.Threading.Tasks.Task<CreditsBurnRate> GetBurnRateAsync(System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            return GetAsync<CreditsBurnRate>("burnrate", null, cancellationToken);
        }

        /// <summary>
        /// Get the daily credits consumption between two dates
        /// </summary>
        /// <param name="from">Start date (inclusive)</param>
        /// <param name="to">End date (inclusive)</param>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual System.Threading.Tasks.Task<System.Collections.Generic.ICollection<CreditsBurnRateTrendItem>> GetBurnRateTrendAsync(System.DateTime from, System.DateTime to, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            var query = $"from={from.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)}&to={to.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)}";
            return GetAsync<System.Collections.Generic.ICollection<CreditsBurnRateTrendItem>>("burnrate/trend", query, cancellationToken);
        }

        /// <summary>
        /// Get the credits cost of each action type (e.g. triage, remediation)
        /// </summary>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual System.Threading.Tasks.Task<CreditsActionRates> GetActionRatesAsync(System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            return GetAsync<CreditsActionRates>("action-rates", null, cancellationToken);
        }

        /// <summary>
        /// Get the credits consumption grouped by action
        /// </summary>
        /// <param name="period">Period, e.g. "last_90_days"</param>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual System.Threading.Tasks.Task<CreditsConsumptionByAction> GetConsumptionByActionAsync(string period = "last_90_days", System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            return GetAsync<CreditsConsumptionByAction>("consumption/by-action", $"period={System.Uri.EscapeDataString(period)}", cancellationToken);
        }

        /// <summary>
        /// Get the top credit consumers
        /// </summary>
        /// <param name="groupBy">Grouping, e.g. "user"</param>
        /// <param name="period">Period, e.g. "last_90_days"</param>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual System.Threading.Tasks.Task<CreditsTopConsumers> GetTopConsumersAsync(string groupBy = "user", string period = "last_90_days", System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            return GetAsync<CreditsTopConsumers>("consumption/top-consumers", $"groupBy={System.Uri.EscapeDataString(groupBy)}&period={System.Uri.EscapeDataString(period)}", cancellationToken);
        }

        private async System.Threading.Tasks.Task<T> GetAsync<T>(string path, string query, System.Threading.CancellationToken cancellationToken)
        {
            var client_ = _httpClient;
            using (var request_ = new System.Net.Http.HttpRequestMessage())
            {
                request_.Method = new System.Net.Http.HttpMethod("GET");
                request_.Headers.Accept.Add(System.Net.Http.Headers.MediaTypeWithQualityHeaderValue.Parse("application/json"));

                var urlBuilder_ = new System.Text.StringBuilder();
                if (!string.IsNullOrEmpty(_baseUrl)) urlBuilder_.Append(_baseUrl);
                urlBuilder_.Append(path);
                if (!string.IsNullOrEmpty(query))
                    urlBuilder_.Append('?').Append(query);

                PrepareRequest(client_, request_, urlBuilder_);

                var url_ = urlBuilder_.ToString();
                if (!System.Uri.TryCreate(url_, System.UriKind.Absolute, out var requestUri_) ||
                    (requestUri_.Scheme != System.Uri.UriSchemeHttps && requestUri_.Scheme != System.Uri.UriSchemeHttp))
                {
                    throw new System.InvalidOperationException("Invalid credits request URL: " + url_);
                }
                request_.RequestUri = requestUri_;

                PrepareRequest(client_, request_, url_);

                var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
                try
                {
                    var headers_ = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.IEnumerable<string>>();
                    foreach (var item_ in response_.Headers)
                        headers_[item_.Key] = item_.Value;
                    if (response_.Content != null && response_.Content.Headers != null)
                    {
                        foreach (var item_ in response_.Content.Headers)
                            headers_[item_.Key] = item_.Value;
                    }

                    ProcessResponse(client_, response_);

                    var status_ = (int)response_.StatusCode;
                    if (status_ == 200)
                    {
#if DEBUG
                        var content = await response_.Content.ReadAsStringAsync();

                        Trace.WriteLine(content);
#endif

                        var objectResponse_ = await ReadObjectResponseAsync<T>(response_, headers_, cancellationToken).ConfigureAwait(false);
                        if (objectResponse_.Object == null)
                        {
                            throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                        }
                        return objectResponse_.Object;
                    }
                    else
                        if (status_ == 400)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<Error>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            throw new ApiException<Error>("Invalid request", status_, objectResponse_.Text, headers_, objectResponse_.Object, null);
                        }
                        else
                            if (status_ == 401)
                            {
                                string responseText_ = (response_.Content == null) ? string.Empty : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                                throw new ApiException("Access token is missing or invalid", status_, responseText_, headers_, null);
                            }
                            else
                            {
                                var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                                throw new ApiException("The HTTP status code of the response was not expected (" + status_ + ").", status_, responseData_, headers_, null);
                            }
                }
                finally
                {
                    response_.Dispose();
                }
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
    }

    public partial class CreditsLicenseStatus
    {
        /// <summary>e.g. "trial_active"</summary>
        [Newtonsoft.Json.JsonProperty("state")]
        public string State { get; set; }

        [Newtonsoft.Json.JsonProperty("startDate")]
        public System.DateTimeOffset? StartDate { get; set; }

        [Newtonsoft.Json.JsonProperty("endDate")]
        public System.DateTimeOffset? EndDate { get; set; }

        [Newtonsoft.Json.JsonProperty("trialStartDate")]
        public System.DateTimeOffset? TrialStartDate { get; set; }

        [Newtonsoft.Json.JsonProperty("trialEndDate")]
        public System.DateTimeOffset? TrialEndDate { get; set; }

        [Newtonsoft.Json.JsonProperty("trialInitialCreditGrant")]
        public decimal? TrialInitialCreditGrant { get; set; }
    }

    public partial class CreditsInfo
    {
        [Newtonsoft.Json.JsonProperty("available")]
        public decimal Available { get; set; }

        [Newtonsoft.Json.JsonProperty("total")]
        public decimal Total { get; set; }

        [Newtonsoft.Json.JsonProperty("used")]
        public decimal Used { get; set; }

        [Newtonsoft.Json.JsonProperty("actionsAvailable")]
        public int ActionsAvailable { get; set; }

        [Newtonsoft.Json.JsonProperty("actionsPerformed")]
        public int ActionsPerformed { get; set; }

        [Newtonsoft.Json.JsonProperty("enforcement")]
        public CreditsEnforcement Enforcement { get; set; }
    }

    public partial class CreditsEnforcement
    {
        /// <summary>e.g. "active"</summary>
        [Newtonsoft.Json.JsonProperty("state")]
        public string State { get; set; }

        [Newtonsoft.Json.JsonProperty("consumptionPct")]
        public decimal ConsumptionPct { get; set; }

        [Newtonsoft.Json.JsonProperty("warningThresholdPct")]
        public decimal WarningThresholdPct { get; set; }

        [Newtonsoft.Json.JsonProperty("cutoffThresholdPct")]
        public decimal CutoffThresholdPct { get; set; }
    }

    public partial class CreditsBurnRate
    {
        [Newtonsoft.Json.JsonProperty("ratePerMonth")]
        public decimal RatePerMonth { get; set; }

        [Newtonsoft.Json.JsonProperty("estimatedDepletionDate")]
        public System.DateTimeOffset? EstimatedDepletionDate { get; set; }
    }

    public partial class CreditsBurnRateTrendItem
    {
        [Newtonsoft.Json.JsonProperty("date")]
        public System.DateTime Date { get; set; }

        [Newtonsoft.Json.JsonProperty("totalCreditsConsumed")]
        public decimal TotalCreditsConsumed { get; set; }
    }

    public partial class CreditsActionRates
    {
        [Newtonsoft.Json.JsonProperty("count")]
        public int Count { get; set; }

        [Newtonsoft.Json.JsonProperty("rates")]
        public System.Collections.Generic.ICollection<CreditsActionRate> Rates { get; set; }
    }

    public partial class CreditsActionRate
    {
        [Newtonsoft.Json.JsonProperty("id")]
        public System.Guid Id { get; set; }

        /// <summary>e.g. "triage", "remediation"</summary>
        [Newtonsoft.Json.JsonProperty("action_type")]
        public string ActionType { get; set; }

        [Newtonsoft.Json.JsonProperty("credits_per_action")]
        public decimal CreditsPerAction { get; set; }

        [Newtonsoft.Json.JsonProperty("display_name")]
        public string DisplayName { get; set; }

        [Newtonsoft.Json.JsonProperty("is_active")]
        public bool IsActive { get; set; }

        [Newtonsoft.Json.JsonProperty("start_date")]
        public System.DateTimeOffset? StartDate { get; set; }

        [Newtonsoft.Json.JsonProperty("metronome_action_id")]
        public string MetronomeActionId { get; set; }

        [Newtonsoft.Json.JsonProperty("metronome_starting_at")]
        public System.DateTimeOffset? MetronomeStartingAt { get; set; }

        [Newtonsoft.Json.JsonProperty("created_at")]
        public System.DateTimeOffset? CreatedAt { get; set; }

        [Newtonsoft.Json.JsonProperty("change_source")]
        public string ChangeSource { get; set; }
    }

    public partial class CreditsConsumptionByAction
    {
        [Newtonsoft.Json.JsonProperty("actions")]
        public System.Collections.Generic.ICollection<CreditsActionConsumption> Actions { get; set; }

        [Newtonsoft.Json.JsonProperty("totalCredits")]
        public decimal TotalCredits { get; set; }

        [Newtonsoft.Json.JsonProperty("total")]
        public int Total { get; set; }
    }

    public partial class CreditsActionConsumption
    {
        [Newtonsoft.Json.JsonProperty("actionDisplayName")]
        public string ActionDisplayName { get; set; }

        [Newtonsoft.Json.JsonProperty("creditsPerAction")]
        public decimal CreditsPerAction { get; set; }

        [Newtonsoft.Json.JsonProperty("totalCredits")]
        public decimal TotalCredits { get; set; }

        [Newtonsoft.Json.JsonProperty("count")]
        public int Count { get; set; }

        [Newtonsoft.Json.JsonProperty("percentage")]
        public decimal Percentage { get; set; }
    }

    public partial class CreditsTopConsumers
    {
        [Newtonsoft.Json.JsonProperty("topActions")]
        public System.Collections.Generic.ICollection<string> TopActions { get; set; }

        [Newtonsoft.Json.JsonProperty("items")]
        public System.Collections.Generic.ICollection<CreditsConsumer> Items { get; set; }
    }

    public partial class CreditsConsumer
    {
        [Newtonsoft.Json.JsonProperty("name")]
        public string Name { get; set; }

        [Newtonsoft.Json.JsonProperty("operations")]
        public System.Collections.Generic.ICollection<CreditsConsumerOperation> Operations { get; set; }
    }

    public partial class CreditsConsumerOperation
    {
        [Newtonsoft.Json.JsonProperty("name")]
        public string Name { get; set; }

        [Newtonsoft.Json.JsonProperty("credits")]
        public decimal Credits { get; set; }
    }
}
