using Application.Dtos.Identity;
using System.Security.Claims;

namespace Application.Configurations.Interfaces.Repositories
{
    public interface ITokenRepository
    {
        Task<TokenDto> CreateTokenAsync(UserDto user, IList<string> roles, IList<Claim>? additionalClaims = null);

        ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);
    }
}