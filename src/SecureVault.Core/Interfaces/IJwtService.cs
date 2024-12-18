using System.Security.Claims;

namespace SecureVault.Core.Interfaces
{
    public interface IJwtService
    {
        string GenerateToken(string userId, IEnumerable<string> roles, IDictionary<string, string> customClaims = null);
        ClaimsPrincipal ValidateToken(string token);
        bool TryValidateToken(string token, out ClaimsPrincipal principal);
        void RevokeToken(string token);
    }
}