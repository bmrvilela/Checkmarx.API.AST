using System.Collections.Generic;
using Newtonsoft.Json;

namespace Checkmarx.API.AST.Models.SCA
{
    public class ExportParameters
    {
        /// <summary>
        /// If you would like to exclude all development and test dependencies from the SBOM, set this flag as true.. Default: false
        /// </summary>
        [JsonProperty("hideDevAndTestDependencies")]
        public bool HideDevAndTestDependencies { get; set; }

        /// <summary>
        /// If you would like to exclude all licenses that aren't marked as "Effective" from the SBOM, set this flag as true. Default: false
        /// </summary>
        [JsonProperty("showOnlyEffectiveLicenses")]
        public bool ShowOnlyEffectiveLicenses { get; set; }

        /// <summary>
        /// Relevant only for scan reports
        /// </summary>
        [JsonProperty("excludePackages")]
        public bool ExcludePackages { get; set; }

        /// <summary>
        /// Relevant only for scan reports
        /// </summary>
        [JsonProperty("excludeLicenses")]
        public bool ExcludeLicenses { get; set; }

        /// <summary>
        /// Relevant only for scan reports
        /// </summary>
        [JsonProperty("excludeVulnerabilities")]
        public bool ExcludeVulnerabilities { get; set; }

        /// <summary>
        /// Relevant only for scan reports
        /// </summary>
        [JsonProperty("excludePolicies")]
        public bool ExcludePolicies { get; set; }


        /// <summary>
        /// Comma separated list of paths to manifest files that will be remediated. Paths are relative to the repo folder
        /// </summary>
        /// <remarks>Relevant only for RemediatedPackagesJson reports</remarks>
        [JsonProperty("filePaths")]
        public List<string> FilePaths { get; set; }

        /// <summary>
        /// If set as true, the output will always be returned in a zip archive. If false (default), then if there is a single filepath the output will be returned as a json.
        /// </summary>
        /// <remarks>If there are multiple filepaths, then the output is always returned as a zip archive, even if this parameter is set as false.</remarks>
        [JsonProperty("compressedOutput")]
        public bool CompressedOutput { get; set; }
    }
}
