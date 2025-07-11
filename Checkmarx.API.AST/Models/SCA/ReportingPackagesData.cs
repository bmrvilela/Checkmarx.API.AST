using Newtonsoft.Json;
using System.Collections.Generic;
using System.Text.Json;

namespace Checkmarx.API.AST.Models.SCA
{
    public partial class ReportingPackagesData
    {
        [JsonProperty("reportingPackages", NullValueHandling = NullValueHandling.Ignore)]
        public List<ReportingPackage> ReportingPackages { get; set; }
    }

}
