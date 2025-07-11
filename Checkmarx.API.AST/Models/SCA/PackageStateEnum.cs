namespace Checkmarx.API.AST.Models.SCA
{
    public enum PackageStateEnum
    {
        [System.Runtime.Serialization.EnumMember(Value = @"Monitored")]
        Monitored,
        [System.Runtime.Serialization.EnumMember(Value = @"Muted")]
        Muted,
        [System.Runtime.Serialization.EnumMember(Value = @"Snooze")]
        Snooze
    }
}
