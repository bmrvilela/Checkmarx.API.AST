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
    }
}
