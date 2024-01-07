using Application.Configurations.Database;
using Domain.Enums;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System.Data;

namespace Infrastructure.Configurations
{
    public class SqlConnectionFactory : ISqlConnectionFactory, IDisposable
    {
        private readonly IConfiguration _configuration;
        private IDbConnection? _connection;
        private bool _disposed = false;
        private ConnectionStringType _connectionStringType;

        public SqlConnectionFactory(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Gets open connection.
        /// </summary>
        /// <returns>IDbConnection.</returns>
        public IDbConnection GetOpenConnection()
        {
            if (_connection == null || _connection.State != ConnectionState.Open)
            {
                switch (_connectionStringType)
                {
                    case ConnectionStringType.PostgresqlConnection:
                        _connection = new NpgsqlConnection(_configuration.GetConnectionString("PostgresqlConnection"));
                        break;

                    case ConnectionStringType.SqlServerConnection:
                        _connection = new SqlConnection(_configuration.GetConnectionString("SqlServerConnection"));
                        break;

                    case ConnectionStringType.DefaultConnection:
                        _connection = new SqlConnection(_configuration.GetConnectionString("DefaultConnection"));
                        break;

                    default:
                        _connection = new SqlConnection(_configuration.GetConnectionString("DefaultConnection"));
                        break;
                }

                _connection.Open();
            }

            return _connection;
        }

        /// <summary>
        /// Initialises new connections.
        /// </summary>
        /// <returns>IDbConnection.</returns>
        public IDbConnection GetNewConnection()
        {
            switch (_connectionStringType)
            {
                case ConnectionStringType.PostgresqlConnection:
                    return new NpgsqlConnection(_configuration.GetConnectionString("PostgresqlConnection"));

                case ConnectionStringType.SqlServerConnection:
                    return new SqlConnection(_configuration.GetConnectionString("SqlServerConnection"));

                case ConnectionStringType.DefaultConnection:
                    return new SqlConnection(_configuration.GetConnectionString("DefaultConnection"));

                default:
                    return new SqlConnection(_configuration.GetConnectionString("DefaultConnection"));
            }
        }

        /// <summary>
        /// Gets connection string and Database type.
        /// </summary>
        /// <returns>The connectionString and The dbType.</returns>
        public (string? connectionString, ConnectionStringType dbType) GetConnectionStringAndDbType()
        {
            switch (_connectionStringType)
            {
                case ConnectionStringType.DefaultConnection:
                    return (_configuration.GetConnectionString("DefaultConnection"), ConnectionStringType.DefaultConnection);

                case ConnectionStringType.SqlServerConnection:
                    return (_configuration.GetConnectionString("SqlServerConnection"), ConnectionStringType.DefaultConnection);

                case ConnectionStringType.PostgresqlConnection:
                    return (_configuration.GetConnectionString("PostgresqlConnection"), ConnectionStringType.PostgresqlConnection);

                case ConnectionStringType.None:
                    return (string.Empty, ConnectionStringType.None);

                default:
                    return default;
            }
        }

        /// <summary>
        /// Sets connection string type.
        /// </summary>
        /// <param name="connectionStringType">The connectionStringType.</param>
        public void SetConnectionStringType(ConnectionStringType connectionStringType)
        {
            _connectionStringType = connectionStringType;
        }

        /// <summary>
        /// Document: https://rules.sonarsource.com/csharp/RSPEC-3881
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing && _connection != null && _connection.State == ConnectionState.Open)
            {
                _connection.Dispose();
            }

            _disposed = true;
        }
    }
}