using Newtonsoft.Json;
using System;
using System.Text.Json;

namespace Checkmarx.API.AST.Models.SCA
{
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

}
