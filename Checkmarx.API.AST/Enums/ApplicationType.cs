using System.Runtime.Serialization;

namespace Checkmarx.API.AST.Enums
{
    public enum ApplicationType
    {
        [EnumMember(Value = @"internal")]
        Internal = 0,

        [EnumMember(Value = @"business")]
        Business = 1,
    }
}
