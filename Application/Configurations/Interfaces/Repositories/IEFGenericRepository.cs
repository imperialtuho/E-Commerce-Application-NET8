namespace Application.Configurations.Interfaces.Repositories
{
    public interface IEFGenericRepository<T> where T : class
    {
        Task<T> GetByIdAsync(object id);

        Task AddAsync(T entity);

        Task AddAndSaveChangesAsync(T entity);

        Task AddRangeAsync(IEnumerable<T> entities);

        Task UpdateAndSaveChangesAsync(T entity);

        Task DeleteAndSaveChangesAsync(T entity);

        Task DeleteRangeAndSaveChangesAsync(IEnumerable<T> entities);

        void DeleteRange(IEnumerable<T> entities);

        Task CommitAsync();
    }
}