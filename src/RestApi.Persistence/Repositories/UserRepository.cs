using Dapper;
using Dapper.Contrib.Extensions;
using RestApi.Domain.V1.Aggregates.Users.Entities;
using RestApi.Domain.V1.Aggregates.Users.Repositories;
using RestApi.Persistence.Context;

namespace RestApi.Persistence.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly DbSession _session;

        public UserRepository(DbSession context)
        {
            _session = context;
        }

        public Task AddAsync(User user, CancellationToken cancellationToken)
        {
            return _session.Connection.InsertAsync(user, _session.Transaction);
        }

        public Task ConfirmEmailAsync(User user)
        {
            string sql = @"
                UPDATE 
                    Users 
                SET 
                    EmailConfirmed = @EmailConfirmed,
                    EmailConfirmationCode = @EmailConfirmationCode
                WHERE Id = @Id";

            return _session.Connection.ExecuteAsync(sql, new { 
                user.Id, 
                user.EmailConfirmationCode,
                user.EmailConfirmed  
            }, 
            _session.Transaction);
        }

        public async Task<User> FindByEmailAsync(string email, bool withPassword = false)
        {
            string sql = 
                @"SELECT 
                    u.Id, u.FirstName, u.LastName, 
                    u.Email, u.ResetPasswordCode, u.ResetPasswordExpiration,
                    u.EmailConfirmationCode";

            if (withPassword)
            {
                sql = $"{sql}, u.PasswordHash";
            }

            sql = $"{sql} FROM Users u WHERE u.Email = @Email";

            return await _session.Connection.QueryFirstOrDefaultAsync<User>(sql, new { Email = email });
        }

        public async Task<User> FindByIdAsync(string userId)
        {
            string sql = @"
                SELECT u.Id, u.FirstName, u.LastName, u.Email, u.Birthdate
                FROM Users u
                WHERE u.Id = @Id
            ";

            return await _session.Connection.QueryFirstOrDefaultAsync<User>(sql, new { Id = userId });
        }

        public async Task<IEnumerable<string>> GetRolesByUserIdAsync(Guid id)
        {
            string sql = @"
                SELECT r.Name FROM UsersRoles ur 
                INNER JOIN Roles r ON ur.RoleId = r.Id 
                INNER JOIN Users u ON ur.UserId = u.Id 
                WHERE u.Id = @UserId
                ORDER BY r.Name ASC";

            return await _session.Connection.QueryAsync<string>(sql, new { UserId = id });
        }

        public async Task UpdatePasswordAsync(User user)
        {
            string sql = @"
                UPDATE 
                    Users 
                SET 
                    PasswordHash = @PasswordHash,
                    ResetPasswordCode = @ResetPasswordCode,
                    ResetPasswordExpiration = @ResetPasswordExpiration 
                WHERE Id = @Id";

            await _session.Connection.ExecuteAsync(sql, new { 
                user.Id, 
                user.PasswordHash,
                user.ResetPasswordCode, 
                user.ResetPasswordExpiration 
            }, 
            _session.Transaction);
        }

        public async Task UpdateResetPasswordCodeAsync(User user)
        {
            string sql = @"
                UPDATE 
                    Users 
                SET 
                    ResetPasswordCode = @ResetPasswordCode,
                    ResetPasswordExpiration = @ResetPasswordExpiration 
                WHERE Id = @Id";

            await _session.Connection.ExecuteAsync(sql, new { 
                user.Id, 
                user.ResetPasswordCode, 
                user.ResetPasswordExpiration 
            },
            _session.Transaction);
        }
    }
}
