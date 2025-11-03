using Checkmarx.API.AST.Services.Analytics;
using System;
using System.Collections.Generic;

namespace Checkmarx.API.AST.Models
{
    public class AnalyticsOptions
    {
        public IEnumerable<string> Projects { get; set; }
        public IEnumerable<string> Applications { get; set; }

        public IEnumerable<string> Branches { get; set; }

        public IEnumerable<string> Environments { get; set; }
        public IEnumerable<ScannerType> Scanners { get; set; }
        public IEnumerable<string> ApplicationTags { get; set; }
        public IEnumerable<string> ProjectTags { get; set; }
        public IEnumerable<string> ScanTags { get; set; }
        public IEnumerable<StateType> States { get; set; }
        public IEnumerable<SeverityType> Severities { get; set; }
    }
}
