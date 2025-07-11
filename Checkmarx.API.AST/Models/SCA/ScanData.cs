using System;
using Newtonsoft.Json;

namespace Checkmarx.API.AST.Models.SCA
{
    public class ScanData
    {
        [JsonProperty("ScanId", Required = Required.Always)]
        public Guid ScanId { get; set; }

        [JsonProperty("FileFormat", Required = Required.Always)]
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public SCAReportFileFormatEnum FileFormat { get; set; }

        [JsonProperty("ExportParameters")]
        public ExportParameters ExportParameters { get; set; }
    }
}
