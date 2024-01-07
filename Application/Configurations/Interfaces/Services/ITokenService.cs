using Application.Dtos.Identity;
using System.Security.Claims;

namespace Application.Configurations.Interfaces.Services
{
    public interface ITokenService
    {
        Task<TokenDto> CreateTokenAsync(UserDto user, IList<string> roles, IList<Claim>? additionalClaims = null);

        ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);
    }
}