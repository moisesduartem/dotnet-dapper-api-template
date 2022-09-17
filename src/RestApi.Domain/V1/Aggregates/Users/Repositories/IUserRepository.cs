﻿using RestApi.Domain.V1.Shared;
using RestApi.Domain.V1.Aggregates.Users.Entities;

namespace RestApi.Domain.V1.Aggregates.Users.Repositories
{
    public interface IUserRepository : IRepository<User>
    {
        Task AddAsync(User user, CancellationToken cancellationToken);
        Task<User> FindByEmailAndPasswordAsync(string email, string hash);
        Task<IEnumerable<string>> GetRolesByUserIdAsync(Guid id);
    }
}
