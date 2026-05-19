using System.Runtime.Serialization;

namespace Checkmarx.API.AST.Enums
{
    public enum RuleType
    {
        [EnumMember(Value = @"project.name.in")]
        Project_name_in = 0,

        [EnumMember(Value = @"project.name.starts-with")]
        Project_name_startsWith = 1,

        [EnumMember(Value = @"project.name.contains")]
        Project_name_contains = 2,

        [EnumMember(Value = @"project.name.regex")]
        Project_name_regex = 3,

        [EnumMember(Value = @"project.tag.key.exists")]
        Project_tag_key_exists = 4,

        [EnumMember(Value = @"project.tag.value.exists")]
        Project_tag_value_exists = 5,

        [EnumMember(Value = @"project.tag.key-value.exists")]
        Project_tag_keyValue_exists = 6,
    }
}
