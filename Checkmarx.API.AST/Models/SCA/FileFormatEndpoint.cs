using System.Collections.Generic;
using Newtonsoft.Json;

namespace Checkmarx.API.AST.Models.SCA
{
    public class FileFormatEndpoint
    {
        [JsonProperty("route")]
        public string Route { get; set; }

        [JsonProperty("fileFormats")]
        public List<SCAReportFileFormatEnum> FileFormats { get; set; }
    }
}
