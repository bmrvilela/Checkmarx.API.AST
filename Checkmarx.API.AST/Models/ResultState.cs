using Checkmarx.API.AST.Models.SCA;
using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.SASTResults;

namespace Checkmarx.API.AST.Models
{
    public abstract class ResultState
    {
        public int Id { get; set; }
        public string Name { get; set; }
    }

    public class SASTResultState : ResultState
    {
        public ResultsState? State { get; set; }
    }

    public class SCAResultState : ResultState
    {
        public ScaVulnerabilityStatus State { get; set; }
    }

    public class KicsResultState : ResultState
    {
        public KicsStateEnum State { get; set; }
    }
}
