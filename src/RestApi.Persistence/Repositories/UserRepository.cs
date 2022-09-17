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

        public async Task<User> FindByEmailAsync(string email)
        {
            string sql = @"
                SELECT u.Id, u.FirstName, u.LastName, u.Email, u.PasswordHash
                FROM Users u
                WHERE u.Email = @Email
            ";

            using var connection = _context.CreateConnection();
            return await connection.QueryFirstOrDefaultAsync<User>(sql, new { Email = email });
        }

        public async Task<IEnumerable<string>> GetRolesByUserIdAsync(Guid id)
        {
            string sql = @"
                SELECT r.Name FROM UsersRoles ur 
                INNER JOIN Roles r ON ur.RoleId = r.Id 
                INNER JOIN Users u ON ur.UserId = u.Id 
                WHERE u.Id = @UserId
                ORDER BY r.Name ASC";

            using var connection = _context.CreateConnection();
            return await connection.QueryAsync<string>(sql, new { UserId = id });
        }
    }
}
