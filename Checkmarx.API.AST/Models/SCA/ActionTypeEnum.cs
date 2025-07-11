namespace Checkmarx.API.AST.Models.SCA
{
    
    [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
    public enum ActionTypeEnum
    {
        [System.Runtime.Serialization.EnumMember(Value = @"ChangeState")]
        ChangeState,

        [System.Runtime.Serialization.EnumMember(Value = @"ChangeScore")]
        ChangeScore,

        [System.Runtime.Serialization.EnumMember(Value = @"GroupStateAndScoreActions")]
        GroupStateAndScoreActions
    }
}
