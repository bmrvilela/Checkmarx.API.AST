using System;
using System.Text.Json.Serialization;
using System.Xml.Linq;

namespace Checkmarx.API.AST.Models.SCA
{
    public class ScaActionItem
    {

        [JsonPropertyName("isComment")]
        public bool IsComment { get; set; }

        [JsonPropertyName("actionType")]
        public ActionTypeEnum ActionType { get; set; }

        [JsonPropertyName("actionValue")]
        public string ActionValue { get; set; }

        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; }

        [JsonPropertyName("createdAt")]
        public DateTimeOffset CreatedAt { get; set; }

        [JsonPropertyName("previousActionValue")]
        public string PreviousActionValue { get; set; }

        [JsonPropertyName("comment")]
        public ScaPredicateComment Comment { get; set; }
    }
}
