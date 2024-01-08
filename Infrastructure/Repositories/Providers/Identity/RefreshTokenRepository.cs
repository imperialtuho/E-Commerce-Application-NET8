using Application.Configurations.Interfaces.Repositories;
using Domain.Entities.Identity;
using Infrastructure.Database;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories.Providers.Identity
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly ApplicationDbContext _dbContext;

        public RefreshTokenRepository(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task AddAsync(RefreshToken token)
        {
            await _dbContext.RefreshTokens.AddAsync(token);
        }

        public async Task CompleteAsync()
        {
            await _dbContext.SaveChangesAsync();
        }

        public async Task<RefreshToken?> FindByTokenAsync(string token)
        {
            return await _dbContext.RefreshTokens.FirstOrDefaultAsync(t => t.Token == token);
        }

        public async Task InvalidateUserTokens(string userId)
        {
            IList<RefreshToken> tokens = await _dbContext.RefreshTokens.Where(rt => rt.UserId == userId).ToListAsync();

            foreach (var t in tokens)
            {
                t.Invalidated = true;
                _dbContext.RefreshTokens.Update(t);
            }
        }

        public void Update(RefreshToken token)
        {
            _dbContext.RefreshTokens.Update(token);
        }
    }
}