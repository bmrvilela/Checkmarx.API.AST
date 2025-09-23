using System.Text.RegularExpressions;
namespace Checkmarx.API.AST.Utils
{
  

    public static class HeaderSanitizer
    {
        // Only allow valid token characters for ProductName
        private static readonly Regex InvalidTokenChars = new Regex(@"[^!#$%&'*+\-.^_`|~0-9a-zA-Z]", RegexOptions.Compiled);

        /// <summary>
        /// Sanitizes a string for use as ProductName in ProductInfoHeaderValue.
        /// </summary>
        public static string SanitizeProductName(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove all invalid characters
            return InvalidTokenChars.Replace(input, "");
        }
    }

}
