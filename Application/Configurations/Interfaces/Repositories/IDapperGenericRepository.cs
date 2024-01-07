using System.Data;

namespace Application.Configurations.Interfaces.Repositories
{
    public interface IDapperGenericRepository<T>
    {
        Task<T> GetAsync(object? id);

        Task<int> AddAsync(T obj);

        Task<bool> UpdateAsync(T obj);

        Task<bool> DeleteAsync(T obj);

        Task<T> QuerySingleOrDefaultAsync(string sql, object? param = null);

        Task<Q> QuerySingleOrDefaultAsync<Q>(string sql, object? param = null) where Q : class;

        Task<T> QuerySingleOrDefaultAsync(IDbConnection dbConnection, string sql, object? param = null);

        Task<Q> QuerySingleOrDefaultAsync<Q>(IDbConnection dbConnection, string sql, object? param = null) where Q : class;

        Task<List<T>> QueryAsync(string sql, object? param = null);

        Task<List<Q>> QueryAsync<Q>(string sql, object? param = null) where Q : class;

        Task<List<T>> QueryAsync(IDbConnection dbConnection, string sql, object? param = null);

        Task<List<Q>> QueryAsync<Q>(IDbConnection dbConnection, string sql, object? param = null) where Q : class;
    }
}