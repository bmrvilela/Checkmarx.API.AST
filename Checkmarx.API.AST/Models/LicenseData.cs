using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Models
{
    public class LicenseData
    {
        [JsonProperty("activationDate")]
        public long ActivationDate { get; set; }

        [JsonProperty("allowedEngines")]
        public List<string> AllowedEngines { get; set; }

        [JsonProperty("apiSecurityEnabled")]
        public bool ApiSecurityEnabled { get; set; }

        [JsonProperty("codeBashingEnabled")]
        public bool CodeBashingEnabled { get; set; }

        [JsonProperty("codeBashingUrl")]
        public string CodeBashingUrl { get; set; }

        [JsonProperty("codeBashingUsersCount")]
        public int CodeBashingUsersCount { get; set; }

        [JsonProperty("customMaxConcurrentScansEnabled")]
        public bool CustomMaxConcurrentScansEnabled { get; set; }

        [JsonProperty("dastEnabled")]
        public bool DastEnabled { get; set; }

        [JsonProperty("expirationDate")]
        public long ExpirationDate { get; set; }

        [JsonProperty("features")]
        public List<string> Features { get; set; }

        [JsonProperty("lastCommentLimit")]
        public int LastCommentLimit { get; set; }

        [JsonProperty("maxConcurrentScans")]
        public int MaxConcurrentScans { get; set; }

        [JsonProperty("maxQueuedScans")]
        public int MaxQueuedScans { get; set; }

        [JsonProperty("retentionPeriod")]
        public int RetentionPeriod { get; set; }

        [JsonProperty("scsEnabled")]
        public bool ScsEnabled { get; set; }

        [JsonProperty("serviceType")]
        public string ServiceType { get; set; }

        [JsonProperty("services")]
        public List<string> Services { get; set; }

        [JsonProperty("unlimitedProjects")]
        public bool UnlimitedProjects { get; set; }

        [JsonProperty("usersCount")]
        public int UsersCount { get; set; }
    }
}
