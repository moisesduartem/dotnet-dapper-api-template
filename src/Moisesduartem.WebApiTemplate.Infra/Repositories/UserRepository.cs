﻿using Moisesduartem.WebApiTemplate.Domain.V1.Aggregates.Users.Entities;
using Moisesduartem.WebApiTemplate.Domain.V1.Aggregates.Users.Repositories;

namespace Moisesduartem.WebApiTemplate.Infra.Repositories
{
    public class UserRepository : IUserRepository
    {
        public Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken)
        {
            var user = new User("Mr. User", "user@email.com", "username", "password123");
            return Task.FromResult<User?>(user);
        }
    }
}
