using Newtonsoft.Json;
using System.Collections.Generic;

namespace Checkmarx.API.AST.Models
{
    public class ContributorInsightsResponse
    {
        [JsonProperty("items")]
        public List<ContributorInsightsGroup> Items { get; set; }
    }

    public class ContributorInsightsGroup
    {
        [JsonProperty("total")]
        public int Total { get; set; }

        [JsonProperty("max")]
        public int Max { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("insights")]
        public List<ContributorInsightEntry> Insights { get; set; }
    }

    public class ContributorInsightEntry
    {
        [JsonProperty("sourceName")]
        public string SourceName { get; set; }

        [JsonProperty("projectCount")]
        public int ProjectCount { get; set; }

        [JsonProperty("contributorCount")]
        public int ContributorCount { get; set; }
    }
}
