using RestApi.Application.V1.Aggregates.Users.Commands;
using RestApi.Application.V1.Aggregates.Users.DTOs;
using RestApi.Application.V1.Aggregates.Users.Queries;
using RestApi.Application.V1.Shared;
using RestApi.Domain.V1.Aggregates.Users.Entities;

namespace RestApi.Application.V1.Services
{
    public interface IIdentityService
    {
        Task<Result> ConfirmEmailAsync(User user, string token);
        Task<User> FindUserByEmailAsync(string email);
        Task<Result> ForgotPasswordAsync(User user, CancellationToken cancellationToken);
        Task<UserProfileDTO?> GetLoggedUserAsync();
        Task<LoginDTO> LoginAsync(LoginQuery query);
        Task<Result> ResetPasswordAsync(User user, string token, string password);
        Task<Result> RegisterAsync(RegisterUserCommand command, CancellationToken cancellationToken);
    }
}
