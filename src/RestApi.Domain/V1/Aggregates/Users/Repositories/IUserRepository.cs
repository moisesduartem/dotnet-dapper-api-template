﻿using RestApi.Domain.V1.Shared;
using RestApi.Domain.V1.Aggregates.Users.Entities;

namespace RestApi.Domain.V1.Aggregates.Users.Repositories
{
    public interface IUserRepository : IRepository<User>
    {
        Task AddAsync(User user, CancellationToken cancellationToken);
        Task<User> FindByEmailAsync(string email, bool withPassword = false);
        Task<User> FindByIdAsync(string userId);
        Task<IEnumerable<string>> GetRolesByUserIdAsync(Guid id);
        Task UpdateResetPasswordCodeAsync(User user);
        Task UpdatePasswordAsync(User user);
        Task ConfirmEmailAsync(User user);
    }
}
