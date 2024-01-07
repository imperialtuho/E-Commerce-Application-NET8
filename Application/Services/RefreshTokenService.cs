using Application.Configurations.Interfaces.Repositories;
using Application.Configurations.Interfaces.Services;
using Domain.Entities.Identity;

namespace Application.Services
{
    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public RefreshTokenService(IRefreshTokenRepository refreshTokenRepository)
        {
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task AddAsync(RefreshToken token)
        {
            await _refreshTokenRepository.AddAsync(token);
        }

        public async Task CompleteAsync()
        {
            await _refreshTokenRepository.CompleteAsync();
        }

        public async Task<RefreshToken?> FindByTokenAsync(string token)
        {
            return await _refreshTokenRepository.FindByTokenAsync(token);
        }

        public async Task InvalidateUserTokens(string userId)
        {
            await _refreshTokenRepository.InvalidateUserTokens(userId);
        }

        public void Update(RefreshToken token)
        {
            _refreshTokenRepository.Update(token);
        }
    }
}