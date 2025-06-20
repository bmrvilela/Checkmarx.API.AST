using System;

namespace Checkmarx.API.AST.Models
{
    
    public class EpssDto
    {
        public string Cve { get; set; }
        public decimal Epss { get; set; }
        public decimal Percentile { get; set; }
        public DateTime Date { get; set; }

        public override string ToString()
        {
            return $" EpssDto Cve: {Cve}, Epss: {Epss}, Percentile: {Percentile}, Date: {Date}";

        }
    }
}