using Application.Configurations.ApplicationSettings;
using Application.Configurations.Interfaces.Repositories;
using Application.Dtos.Identity;
using Domain.Entities.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Infrastructure.Repositories.Providers.Identity
{
    public class JwtTokenRepository : ITokenRepository
    {
        private readonly JwtSettings _jwtSettings;

        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public JwtTokenRepository(
            IOptions<JwtSettings> options,
            IRefreshTokenRepository refreshTokenRepository)
        {
            _jwtSettings = options.Value;
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task<TokenDto> CreateTokenAsync(UserDto user, IList<string> roles, IList<Claim>? additionalClaims = null)
        {
            var expiration = DateTime.UtcNow.AddSeconds(double.Parse(_jwtSettings.TokenValidityInSeconds));

            JwtSecurityToken token = CreateJwtToken(
                CreateClaims(user, roles, additionalClaims),
                CreateSigningCredentials(),
                expiration
            );

            var tokenHandler = new JwtSecurityTokenHandler();

            var refreshToken = new RefreshToken
            {
                Token = GenerateRefreshToken(),
                JwtId = token.Id,
                UserId = user.Id,
                CreationDate = DateTime.Now,
                ExpiryDate = DateTime.Now.AddDays(double.Parse(_jwtSettings.RefreshTokenValidityInDays))
            };

            await _refreshTokenRepository.AddAsync(refreshToken);
            await _refreshTokenRepository.CompleteAsync();

            return new TokenDto
            {
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken.Token
            };
        }

        private JwtSecurityToken CreateJwtToken(Claim[] claims, SigningCredentials credentials, DateTime expiration) =>
            new JwtSecurityToken(
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims,
                expires: expiration,
                signingCredentials: credentials
            );

        private Claim[] CreateClaims(UserDto user, IList<string> roles, IList<Claim>? additionalClaims = null)
        {
            long iat = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds();

            var claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub, _jwtSettings.Subject),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, iat.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email)
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            if (additionalClaims != null && additionalClaims.Any())
            {
                foreach (var claim in additionalClaims)
                {
                    claims.Add(claim);
                }
            }

            return claims.ToArray();
        }

        private SigningCredentials CreateSigningCredentials() => new(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)), SecurityAlgorithms.HmacSha256);

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                ValidAudience = _jwtSettings.Audience,
                ValidIssuer = _jwtSettings.Issuer,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg
                                                                          .Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                return null;
            }

            return principal;
        }
    }
}