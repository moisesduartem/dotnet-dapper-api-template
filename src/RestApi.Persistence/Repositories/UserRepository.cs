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
    }
}
