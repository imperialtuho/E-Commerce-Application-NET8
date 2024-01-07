using Application.Configurations.Interfaces.Repositories;
using Application.Configurations.Interfaces.Services;
using Application.Dtos.Identity;
using System.Security.Claims;

namespace Application.Services
{
    public class TokenService : ITokenService
    {
        private readonly ITokenRepository _tokenRepository;

        public TokenService(ITokenRepository tokenRepository)
        {
            _tokenRepository = tokenRepository;
        }

        public async Task<TokenDto> CreateTokenAsync(UserDto user, IList<string> roles, IList<Claim>? additionalClaims = null)
        {
            return await _tokenRepository.CreateTokenAsync(user, roles, additionalClaims);
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            return _tokenRepository.GetPrincipalFromExpiredToken(token);
        }
    }
}