namespace Checkmarx.API.AST
{
    // Hand-written companion to the NSwag-generated SSCSReader.cs (not touched by regeneration).
    // GetProjectsAsync/GetEngineResultsByProjectAsync only ever return one page — nothing in the
    // generated client loops "currentPage" to fetch everything, so a single call silently returns
    // just page 1. These two helpers do that looping. currentPage is 1-based (GetProjectsAsync's own
    // generated default is "currentPage = 1"), so the loop starts there.
    public partial class SSCSReader
    {
        public virtual async System.Threading.Tasks.Task<System.Collections.Generic.List<SCSSProject>> GetAllProjectsAsync(
            int pageSize = 100, string filters = null, string sort = null, string search = null,
            System.Threading.CancellationToken cancellationToken = default)
        {
            var all = new System.Collections.Generic.List<SCSSProject>();

            var currentPage = 1;
            while (true)
            {
                var page = await GetProjectsAsync(pageSize, currentPage, filters, sort, search, cancellationToken).ConfigureAwait(false);
                if (page.Entries != null)
                    all.AddRange(page.Entries);

                var total = filters != null ? page.TotalFilteredCount : page.TotalCount;
                if (page.Entries == null || page.Entries.Count < pageSize || all.Count >= total)
                    break;

                currentPage++;
            }

            return all;
        }

        public virtual async System.Threading.Tasks.Task<System.Collections.Generic.List<EngineResult>> GetAllEngineResultsByProjectAsync(
            System.Guid projectId, string engine, System.Guid scan, string filters, int pageSize = 100, string sort = null, string search = null,
            System.Threading.CancellationToken cancellationToken = default)
        {
            var all = new System.Collections.Generic.List<EngineResult>();

            var currentPage = 1;
            while (true)
            {
                var page = await GetEngineResultsByProjectAsync(projectId, engine, scan, filters, pageSize, currentPage, sort, search, cancellationToken).ConfigureAwait(false);
                if (page.Entries != null)
                    all.AddRange(page.Entries);

                if (page.Entries == null || page.Entries.Count < pageSize || all.Count >= page.TotalCount)
                    break;

                currentPage++;
            }

            return all;
        }
    }
}
