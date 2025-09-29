namespace Checkmarx.API.AST.Models.SCA
{
    #region ScanLatestChanges

    public class ScanLatestChangesData
    {
        public ScanLatestChangesCounters scanLatestChanges { get; set; }
    }

    public class ScanLatestChanges
    {
        public ScanLatestChangesData data { get; set; }

        public bool HasVulnerabilityChanges
        {
            get
            {
                return data?.scanLatestChanges?.vulnerabilityModelChangesCounter > 0;
            }
        }
    }

    public class ScanLatestChangesCounters
    {
        public int supplyChainRiskChangesCounter { get; set; }
        public int vulnerabilityModelChangesCounter { get; set; }
        public int packageModelChangesCounter { get; set; }
        public int directPackagesChangeCounter { get; set; }
        public int transitivePackagesChangeCounter { get; set; }
        public int licenseModelChangesCounter { get; set; }
    }

    #endregion

}
