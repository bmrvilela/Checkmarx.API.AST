using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace Checkmarx.API.AST.Utils
{
    public static class JwtUtils
    {
        public static Dictionary<string, List<string>> GetTokenClaims(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentNullException(nameof(token), "Token cannot be null or empty.");

            var handler = new JwtSecurityTokenHandler();

            if (string.IsNullOrWhiteSpace(token) || !handler.CanReadToken(token))
                return null;

            var jwt = handler.ReadJwtToken(token);

            return jwt.Claims.GroupBy(c => c.Type).ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToList());
        }
    }
}
