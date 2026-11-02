using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.RegularExpressions;

namespace Checkmarx.API.AST.Utils
{
    /// <summary>
    /// Thrown when a CxOne API key cannot be used to work out the connection details.
    /// The message is meant to be shown to the user as is.
    /// </summary>
    public class InvalidApiKeyException : ArgumentException
    {
        private readonly string _message;

        public InvalidApiKeyException(string message) : base(message, "apiKey")
        {
            _message = message;
        }

        // ArgumentException appends "(Parameter 'apiKey')", which only adds noise to a message shown to the user
        public override string Message => _message;
    }

    /// <summary>
    /// The connection details that can be worked out from a CxOne API key alone, without any network call.
    /// The key is a Keycloak offline token whose <c>iss</c> claim is
    /// <c>https://{iam-host}/auth/realms/{tenant}</c> - exactly what the token endpoint needs.
    /// The key does not carry the AST server. <see cref="ASTServer"/> is only a provisional guess;
    /// the authoritative value is the <c>ast-base-url</c> claim of the access token the key is exchanged for.
    /// </summary>
    public sealed class ApiKeyInfo
    {
        private static readonly Regex RealmPath = new Regex(@"^/auth/realms/(?<tenant>[^/]+)/?$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>The API key, trimmed.</summary>
        public string ApiKey { get; private set; }

        public Uri AccessControlServer { get; private set; }

        public string Tenant { get; private set; }

        /// <summary>
        /// Best guess of the AST server: the SaaS IAM host with its "iam" label swapped for "ast"
        /// (eu.iam.checkmarx.net -> eu.ast.checkmarx.net), or the issuer host itself when there is no "iam"
        /// label (single tenant installs serve both on the same host).
        /// </summary>
        public Uri ASTServer { get; private set; }

        /// <summary>When the key expires, or null if it does not carry an expiration.</summary>
        public DateTime? ExpiresAtUtc { get; private set; }

        private ApiKeyInfo() { }

        /// <exception cref="InvalidApiKeyException">The key is empty, is not a token, or is not an API key for CxOne.</exception>
        public static ApiKeyInfo Parse(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new InvalidApiKeyException("The API key is empty.");

            apiKey = apiKey.Trim();

            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt;
            try
            {
                if (!handler.CanReadToken(apiKey))
                    throw new FormatException();

                jwt = handler.ReadJwtToken(apiKey);
            }
            catch (Exception ex) when (!(ex is InvalidApiKeyException))
            {
                throw new InvalidApiKeyException("The value provided is not a valid API key, it could not be read as a token. Make sure the whole key was copied.");
            }

            var type = jwt.Claims.FirstOrDefault(c => c.Type == "typ")?.Value;
            if (string.Equals(type, "Bearer", StringComparison.OrdinalIgnoreCase))
                throw new InvalidApiKeyException("The value provided is an access token, not an API key. Access tokens expire after a few minutes. Use the API key generated in Checkmarx One.");

            if (!string.Equals(type, "Offline", StringComparison.OrdinalIgnoreCase) && !string.Equals(type, "Refresh", StringComparison.OrdinalIgnoreCase))
                throw new InvalidApiKeyException($"The value provided is not an API key: unexpected token type '{type ?? "(none)"}', expected 'Offline'.");

            var issuer = jwt.Issuer;
            if (string.IsNullOrWhiteSpace(issuer))
                throw new InvalidApiKeyException("The API key does not contain an issuer ('iss'), so the Access Control server and tenant cannot be determined from it.");

            if (!Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
                throw new InvalidApiKeyException($"The API key issuer '{issuer}' is not a valid URL.");

            // The key is posted to the issuer host, so never over plain http (except a local development server).
            if (issuerUri.Scheme != Uri.UriSchemeHttps && !(issuerUri.Scheme == Uri.UriSchemeHttp && issuerUri.IsLoopback))
                throw new InvalidApiKeyException($"The API key issuer '{issuer}' does not use https.");

            var realm = RealmPath.Match(issuerUri.AbsolutePath);
            if (!realm.Success)
                throw new InvalidApiKeyException($"The API key issuer '{issuer}' does not have the expected format 'https://<host>/auth/realms/<tenant>'.");

            // jwt.ValidTo is DateTime.MinValue when the key has no 'exp'
            DateTime? expiresAt = jwt.ValidTo == DateTime.MinValue ? (DateTime?)null : jwt.ValidTo;
            if (expiresAt.HasValue && expiresAt.Value <= DateTime.UtcNow)
                throw new InvalidApiKeyException($"The API key expired on {expiresAt.Value:yyyy-MM-dd HH:mm} UTC.");

            var origin = new Uri(issuerUri.GetLeftPart(UriPartial.Authority) + "/");

            return new ApiKeyInfo
            {
                ApiKey = apiKey,
                AccessControlServer = origin,
                Tenant = Uri.UnescapeDataString(realm.Groups["tenant"].Value),
                ASTServer = deriveAstServer(origin),
                ExpiresAtUtc = expiresAt
            };
        }

        public static bool TryParse(string apiKey, out ApiKeyInfo info, out string error)
        {
            try
            {
                info = Parse(apiKey);
                error = null;
                return true;
            }
            catch (InvalidApiKeyException ex)
            {
                info = null;
                error = ex.Message;
                return false;
            }
        }

        private static Uri deriveAstServer(Uri origin)
        {
            var labels = origin.Host.Split('.');
            var iam = Array.FindIndex(labels, l => string.Equals(l, "iam", StringComparison.OrdinalIgnoreCase));
            if (iam < 0)
                return origin;

            labels[iam] = "ast";
            return new UriBuilder(origin) { Host = string.Join(".", labels) }.Uri;
        }
    }
}
