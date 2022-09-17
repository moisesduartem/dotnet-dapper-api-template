using Dapper;
using Dapper.Contrib.Extensions;
using Microsoft.Data.SqlClient;
using RestApi.Domain.V1.Aggregates.Users.Entities;
using RestApi.Domain.V1.Aggregates.Users.Repositories;
using RestApi.Persistence.Context;

namespace RestApi.Persistence.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly RestApiContext _context;

        public UserRepository(RestApiContext context)
        {
            _context = context;
        }

        public async Task AddAsync(User user, CancellationToken cancellationToken)
        {
            using var connection = _context.CreateConnection();
            
            await connection.InsertAsync(user);
        }

        public Task<User> FindByEmailAndPasswordAsync(string email, string hash)
        {
            using var connection = _context.CreateConnection();
        }

        public Task<IEnumerable<string>> GetRolesByUserIdAsync(Guid id)
        {
            using var connection = _context.CreateConnection();

            string sql = @"
                SELECT [r].[Name] FROM [UsersRoles] [ur] 
                INNER JOIN [Roles] [r] ON [ur].[RoleId] = [r].[Id] 
                INNER JOIN [Users] [u] ON [ur].[UserId] = [u].[Id] 
                WHERE [u].[Id] = @UserId
                ORDER BY [r].[Name] ASC";

            return connection.QueryAsync<string>(sql, new SqlParameter("UserId", id));
        }
    }
}
