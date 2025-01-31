using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using static Checkmarx.API.AST.ASTClient;

namespace Checkmarx.API.AST.Services
{
    public partial class SASTQuery
    {
        private string _baseUrl;
        private System.Net.Http.HttpClient _httpClient;

        public SASTQuery(string baseUrl, System.Net.Http.HttpClient httpClient)
        {
            _baseUrl = baseUrl;
            _httpClient = httpClient;
        }

        public IEnumerable<Query> GetQueries()
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries";

            return _genericRetryPolicy.Execute(() =>
            {
                using (var requestMessage = new HttpRequestMessage(HttpMethod.Get, serverRestEndpoint))
                {
                    requestMessage.Headers.Authorization = _httpClient.DefaultRequestHeaders.Authorization;

                    try
                    {
                        using (var response = _httpClient.Send(requestMessage, HttpCompletionOption.ResponseHeadersRead))
                        {
                            if (!response.IsSuccessStatusCode)
                            {
                                throw new HttpRequestException($"Server response HTTP status: {response.StatusCode} ({(int)response.StatusCode})");
                            }

                            var responseFromServer = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                            return JsonConvert.DeserializeObject<IEnumerable<Query>>(responseFromServer);
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        throw new Exception("An error occurred while fetching queries.", ex);
                    }
                }
            });
        }

        public IEnumerable<Query> GetQueriesForProject(Guid projId)
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries?projectId={projId}";

            return _genericRetryPolicy.Execute(() =>
            {
                using (var requestMessage = new HttpRequestMessage(HttpMethod.Get, serverRestEndpoint))
                {
                    requestMessage.Headers.Authorization = _httpClient.DefaultRequestHeaders.Authorization;

                    try
                    {
                        using (var response = _httpClient.Send(requestMessage, HttpCompletionOption.ResponseHeadersRead))
                        {
                            if (!response.IsSuccessStatusCode)
                            {
                                throw new HttpRequestException($"Server response HTTP status: {response.StatusCode} ({(int)response.StatusCode})");
                            }

                            var responseFromServer = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                            return JsonConvert.DeserializeObject<IEnumerable<Query>>(responseFromServer);
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        throw new Exception("An error occurred while fetching queries.", ex);
                    }
                }
            });
        }

        public partial class Query
        {
            [Newtonsoft.Json.JsonProperty("id", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string Id { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("name", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string Name { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("group", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string Group { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("level", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string Level { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("lang", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string Lang { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("severity", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string Severity { get; set; }

            [Newtonsoft.Json.JsonProperty("isExecutable", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public bool IsExecutable { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("source", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string Source { get; set; } = default!;

            private System.Collections.Generic.IDictionary<string, object>? _additionalProperties;

            [Newtonsoft.Json.JsonExtensionData]
            public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
            {
                get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
                set { _additionalProperties = value; }
            }

            public string Path => $"queries/{Lang}/{Group}/{Name}.cs";

            public string ToJson()
            {

                return Newtonsoft.Json.JsonConvert.SerializeObject(this, new Newtonsoft.Json.JsonSerializerSettings());

            }
            public static Query FromJson(string data)
            {

                return Newtonsoft.Json.JsonConvert.DeserializeObject<Query>(data, new Newtonsoft.Json.JsonSerializerSettings());

            }

        }
    }
}
