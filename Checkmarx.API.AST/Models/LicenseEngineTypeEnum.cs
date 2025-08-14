using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Models
{
    public enum LicenseEngineTypeEnum
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
        RepositoryHealth,

        [Description("Checkmarx One Assist")]
        CheckmarxOneAssist
    }
}
