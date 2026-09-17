using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Models.SCA
{
    public class PackagesVariables
    {
        [JsonPropertyName("scanId")]
        public Guid ScanId { get; set; }

        [JsonPropertyName("where")]
        public Where Where { get; set; }

        [JsonPropertyName("take")]
        public int Take { get; set; }

        [JsonPropertyName("skip")]
        public int Skip { get; set; }

        [JsonPropertyName("order")]
        public Order Order { get; set; }

        [JsonPropertyName("isExploitablePathEnabled")]
        public bool IsExploitablePathEnabled { get; set; }

        [JsonPropertyName("includeDependencyPaths")]
        public bool IncludeDependencyPaths { get; set; }
    }

    public class IsPrivateDependency
    {
        [JsonPropertyName("neq")]
        public bool Neq { get; set; }
    }

    public class IsSaasProvider
    {
        [JsonPropertyName("eq")]
        public bool Eq { get; set; }
    }

    public class IsUnresolved
    {
        [JsonPropertyName("eq")]
        public bool Eq { get; set; }
    }

    public class Or
    {
        [JsonPropertyName("eq")]
        public string Eq { get; set; }
    }

    public class Order
    {
        [JsonPropertyName("risks")]
        public string Risks { get; set; }
    }

    public class Relation
    {
        [JsonPropertyName("or")]
        public List<Or> Or { get; set; }
    }

    public class Where
    {
        [JsonPropertyName("relation")]
        public Relation Relation { get; set; }

        [JsonPropertyName("isPrivateDependency")]
        public IsPrivateDependency IsPrivateDependency { get; set; }

        [JsonPropertyName("isSaasProvider")]
        public IsSaasProvider IsSaasProvider { get; set; }

        [JsonPropertyName("isUnresolved")]
        public IsUnresolved IsUnresolved { get; set; }
    }
}
