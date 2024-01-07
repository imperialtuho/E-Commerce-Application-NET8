using Application.Configurations.Database;
using Application.Configurations.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories.Providers
{
    public abstract class EFGenericRepository<C, T> : IEFGenericRepository<T>
        where T : class
        where C : DbContext
    {
        protected C _dbContext;
        protected ISqlConnectionFactory _sqlConnectionFactory;

        protected EFGenericRepository(DbContextOptions<C> options, ISqlConnectionFactory sqlConnectionFactory)
        {
            _sqlConnectionFactory = sqlConnectionFactory;
            _dbContext = Activator.CreateInstance(typeof(C), options) as C ?? throw new InvalidOperationException("Cannot create DbContext");
        }

        public virtual async Task AddAndSaveChangesAsync(T entity)
        {
            await _dbContext.Set<T>().AddAsync(entity);
            await _dbContext.SaveChangesAsync();
            _dbContext.Entry(entity).State = EntityState.Unchanged;
        }

        public async Task AddAsync(T entity)
        {
            await _dbContext.Set<T>().AddAsync(entity);
        }

        public async Task AddRangeAsync(IEnumerable<T> entities)
        {
            await _dbContext.Set<T>().AddRangeAsync(entities);
        }

        public async Task CommitAsync()
        {
            await _dbContext.SaveChangesAsync();
        }

        public virtual async Task<T> GetByIdAsync(object id)
        {
            return await _dbContext.Set<T>().FindAsync(id) ?? throw new NotFoundException($"{id}", nameof(T));
        }

        public async Task UpdateAndSaveChangesAsync(T entity)
        {
            _dbContext.Entry(entity).State = EntityState.Modified;
            await _dbContext.SaveChangesAsync();
            _dbContext.Entry(entity).State = EntityState.Unchanged;
        }

        public async Task DeleteAndSaveChangesAsync(T entity)
        {
            _dbContext.Set<T>().Remove(entity);
            await _dbContext.SaveChangesAsync();
        }

        public async Task DeleteRangeAndSaveChangesAsync(IEnumerable<T> entities)
        {
            _dbContext.Set<T>().RemoveRange(entities);
            await _dbContext.SaveChangesAsync();
        }

        public void DeleteRange(IEnumerable<T> entities)
        {
            _dbContext.Set<T>().RemoveRange(entities);
        }
    }
}