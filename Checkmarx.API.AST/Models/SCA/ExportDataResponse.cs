using System;
using Newtonsoft.Json;

namespace Checkmarx.API.AST.Models.SCA
{
    public class ExportDataResponse
    {
        [JsonProperty("exportId")]
        public Guid ExportId { get; set; }
    }
}
