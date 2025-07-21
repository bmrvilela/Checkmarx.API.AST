using Checkmarx.API.AST.Utils;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Models
{
    public class LicenseDto
    {
        [JsonProperty("ID")]
        public int ID { get; set; }

        [JsonProperty("TenantID")]
        public string TenantID { get; set; }

        [JsonProperty("IsActive")]
        public bool IsActive { get; set; }

        [JsonProperty("PackageID")]
        public int PackageID { get; set; }

        [JsonProperty("LicenseData")]
        public LicenseData LicenseData { get; set; }

        [JsonProperty("PackageName")]
        public string PackageName { get; set; }

        private IEnumerable<LicenseEngineType> _allowedEngines = null;
        public IEnumerable<LicenseEngineType> AllowedEngines
        {
            get
            {
                if (_allowedEngines == null)
                {
                    var engineStrings = LicenseData?.AllowedEngines;
                    if (engineStrings == null)
                        _allowedEngines = Enumerable.Empty<LicenseEngineType>();
                    else
                        _allowedEngines = engineStrings
                            .Select(EnumUtils.GetEnumValueByDescription<LicenseEngineType>)
                            .ToList();
                }

                return _allowedEngines;
            }
        }
    }

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

    public enum LicenseEngineType
    {
        [Description("SAST")]
        SAST,

        [Description("API Security")]
        APISecurity,

        [Description("SCA")]
        SCA,

        [Description("Application Risk Management")]
        ApplicationRiskManagement,

        [Description("Containers")]
        Containers,

        [Description("Fusion")]
        Fusion,

        [Description("DAST")]
        DAST,

        [Description("Malicious Packages")]
        MaliciousPackages,

        [Description("SCS")]
        SCS,

        [Description("KICS")]
        KICS,

        [Description("Enterprise Secrets")]
        EnterpriseSecrets,

        [Description("AI Protection")]
        AIProtection,

        [Description("Codebashing")]
        Codebashing,

        [Description("Cloud Insights")]
        CloudInsights,

        [Description("Secret Detection")]
        SecretDetection,

        [Description("Repository Health")]
        RepositoryHealth
    }
}
