namespace Checkmarx.API.AST
{
    public enum SCAReportFileFormatEnum
    {
        [System.Runtime.Serialization.EnumMember(Value = @"CycloneDxJson")]
        CycloneDxJson,
        [System.Runtime.Serialization.EnumMember(Value = @"CycloneDxXml")]
        CycloneDxXml,
        [System.Runtime.Serialization.EnumMember(Value = @"SpdxJson")]
        SpdxJson,
        [System.Runtime.Serialization.EnumMember(Value = @"RemediatedPackages")]
        RemediatedPackages,
        [System.Runtime.Serialization.EnumMember(Value = @"RemediatedPackagesJson")]
        RemediatedPackagesJson,
        [System.Runtime.Serialization.EnumMember(Value = @"ScanReportJson")]
        ScanReportJson,
        [System.Runtime.Serialization.EnumMember(Value = @"ScanReportXml")]
        ScanReportXml,
        [System.Runtime.Serialization.EnumMember(Value = @"ScanReportCsv")]
        ScanReportCsv,
        [System.Runtime.Serialization.EnumMember(Value = @"ScanReportPdf")]
        ScanReportPdf,
        [System.Runtime.Serialization.EnumMember(Value = @"DynamicXml")]
        DynamicXml,
        [System.Runtime.Serialization.EnumMember(Value = @"DynamicJson")]
        DynamicJson,
        [System.Runtime.Serialization.EnumMember(Value = @"DynamicCsv")]
        DynamicCsv
    }
}