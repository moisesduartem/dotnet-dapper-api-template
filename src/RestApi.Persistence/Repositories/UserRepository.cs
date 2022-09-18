using Dapper;
using Dapper.Contrib.Extensions;
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

        public async Task<User> FindByEmailAsync(string email, bool withPassword = false)
        {
            string sql = 
                @"SELECT 
                    u.Id, u.FirstName, u.LastName, 
                    u.Email, u.ResetPasswordCode, u.ResetPasswordExpiration";

            if (withPassword)
            {
                sql = $"{sql}, u.PasswordHash";
            }

            sql = $"{sql} FROM Users u WHERE u.Email = @Email";

            using var connection = _context.CreateConnection();
            return await connection.QueryFirstOrDefaultAsync<User>(sql, new { Email = email });
        }

        public async Task<User> FindByIdAsync(string userId)
        {
            string sql = @"
                SELECT u.Id, u.FirstName, u.LastName, u.Email, u.Birthdate
                FROM Users u
                WHERE u.Id = @Id
            ";

            using var connection = _context.CreateConnection();
            return await connection.QueryFirstOrDefaultAsync<User>(sql, new { Id = userId });
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

        public async Task UpdatePasswordAsync(User user)
        {
            string sql = @"
                UPDATE 
                    Users 
                SET 
                    PasswordHash = @Hash,
                    ResetPasswordCode = @Code,
                    ResetPasswordExpiration = @Expiration 
                WHERE Id = @UserId";

            using var connection = _context.CreateConnection();
            await connection.ExecuteAsync(sql, new { 
                UserId = user.Id, 
                Hash = user.PasswordHash,
                Code = user.ResetPasswordCode, 
                Expiration = user.ResetPasswordExpiration 
            });
        }

        public async Task UpdateResetPasswordCodeAsync(User user)
        {
            string sql = @"
                UPDATE 
                    Users 
                SET 
                    ResetPasswordCode = @Code,
                    ResetPasswordExpiration = @Expiration 
                WHERE Id = @UserId";

            using var connection = _context.CreateConnection();
            await connection.ExecuteAsync(sql, new { 
                UserId = user.Id, 
                Code = user.ResetPasswordCode, 
                Expiration = user.ResetPasswordExpiration 
            });
        }
    }
}
