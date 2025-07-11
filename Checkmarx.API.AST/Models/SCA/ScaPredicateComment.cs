using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Models.SCA
{

    public class ScaPredicateComment
    {
        [JsonPropertyName("id")]
        public Guid Id { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }

        [JsonPropertyName("createdOn")]
        public DateTimeOffset CreatedOn { get; set; } // Use DateTimeOffset for Z-suffixed ISO 8601 dates

        [JsonPropertyName("userName")]
        public string UserName { get; set; }
    }
}
