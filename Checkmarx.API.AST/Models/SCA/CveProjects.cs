using Newtonsoft.Json;
using System.Text.Json;

namespace Checkmarx.API.AST.Models.SCA
{
    public partial class CveProjects
    {
        [JsonProperty("data", NullValueHandling = NullValueHandling.Ignore)]
        public ReportingPackagesData Data { get; set; }
    }

}
