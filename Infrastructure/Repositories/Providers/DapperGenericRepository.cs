using Application.Configurations.Database;
using Application.Configurations.Interfaces.Repositories;
using Dapper;
using Dapper.Contrib.Extensions;
using System.Data;

namespace Infrastructure.Repositories.Providers
{
    public abstract class DapperGenericRepository<T> : IDapperGenericRepository<T> where T : class
    {
        private readonly ISqlConnectionFactory _sqlConnectionFactory;

        protected DapperGenericRepository(ISqlConnectionFactory sqlConnectionFactory)
        {
            _sqlConnectionFactory = sqlConnectionFactory;
            SqlMapper.Settings.CommandTimeout = 300;
        }

        public async Task<T> GetAsync(object? id)
        {
            using IDbConnection connection = _sqlConnectionFactory.GetNewConnection();

            return await connection.GetAsync<T>(id).ConfigureAwait(false);
        }

        public async Task<int> AddAsync(T obj)
        {
            using IDbConnection connection = _sqlConnectionFactory.GetNewConnection();

            return await connection.InsertAsync(obj).ConfigureAwait(false);
        }

        public async Task<bool> UpdateAsync(T obj)
        {
            using IDbConnection connection = _sqlConnectionFactory.GetNewConnection();

            return await connection.UpdateAsync(obj).ConfigureAwait(false);
        }

        public async Task<bool> DeleteAsync(T obj)
        {
            using IDbConnection connection = _sqlConnectionFactory.GetNewConnection();

            return await connection.DeleteAsync(obj).ConfigureAwait(false);
        }

        public async Task<List<T>> QueryAsync(string sql, object? param = null)
        {
            using IDbConnection connection = _sqlConnectionFactory.GetNewConnection();
            List<T> query = await QueryAsync(connection, sql, param).ConfigureAwait(false);

            return query.AsList();
        }

        public async Task<List<T>> QueryAsync(IDbConnection dbConnection, string sql, object? param = null)
        {
            IEnumerable<T> query = await dbConnection.QueryAsync<T>(sql, param).ConfigureAwait(false);

            return query.AsList();
        }

        public async Task<List<Q>> QueryAsync<Q>(IDbConnection dbConnection, string sql, object? param = null) where Q : class
        {
            IEnumerable<Q> query = await dbConnection.QueryAsync<Q>(sql, param);

            return query.AsList();
        }

        public async Task<List<Q>> QueryAsync<Q>(string sql, object? param = null) where Q : class
        {
            using IDbConnection connection = _sqlConnectionFactory.GetNewConnection();
            IEnumerable<Q> query = await QueryAsync<Q>(connection, sql, param).ConfigureAwait(false);

            return query.AsList();
        }

        public async Task<T> QuerySingleOrDefaultAsync(IDbConnection dbConnection, string sql, object? param = null)
        {
            return await dbConnection.QuerySingleOrDefaultAsync<T>(sql, param).ConfigureAwait(false) ?? throw new NotFoundException($"{param}", nameof(T));
        }

        public async Task<T> QuerySingleOrDefaultAsync(string sql, object? param = null)
        {
            using IDbConnection connection = _sqlConnectionFactory.GetNewConnection();

            return await QuerySingleOrDefaultAsync(connection, sql, param).ConfigureAwait(false);
        }

        public async Task<Q> QuerySingleOrDefaultAsync<Q>(IDbConnection dbConnection, string sql, object? param = null) where Q : class
        {
            return await dbConnection.QuerySingleOrDefaultAsync<Q>(sql, param) ?? throw new NotFoundException($"{param}", nameof(T));
        }

        public async Task<Q> QuerySingleOrDefaultAsync<Q>(string sql, object? param = null) where Q : class
        {
            using IDbConnection connection = _sqlConnectionFactory.GetNewConnection();

            return await QuerySingleOrDefaultAsync<Q>(connection, sql, param).ConfigureAwait(false);
        }
    }
}