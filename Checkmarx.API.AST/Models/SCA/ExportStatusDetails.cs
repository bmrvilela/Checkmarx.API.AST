using System;
using Newtonsoft.Json;

namespace Checkmarx.API.AST.Models.SCA
{
    public class ExportStatusDetails
    {
        const string Completed = "Completed";
        const string Failed = "Failed";

        [JsonProperty("exportId")]
        public Guid ExportId { get; set; }

        [JsonProperty("exportStatus")]
        public string ExportStatus { get; set; }

        [JsonProperty("fileUrl")]
        public string FileUrl { get; set; }

        public bool IsCompleted()
        {
            return ExportStatus == Completed;
        }

        public bool IsFailed()
        {
            return ExportStatus == Failed;
        }
    }
}
