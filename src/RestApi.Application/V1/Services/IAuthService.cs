using ErrorOr;
using RestApi.Application.V1.Aggregates.Users.Commands;
using RestApi.Application.V1.Aggregates.Users.DTOs;
using RestApi.Application.V1.Aggregates.Users.Queries;
using RestApi.Domain.V1.Aggregates.Users.Entities;

namespace RestApi.Application.V1.Services
{
    public interface IAuthService
    {
        Task<ErrorOr<Success>> ConfirmEmailAsync(User user, string token);
        Task<User> FindUserByEmailAsync(string email);
        Task<ErrorOr<Success>> ForgotPasswordAsync(User user, CancellationToken cancellationToken);
        Task<ErrorOr<UserProfileDTO>> GetLoggedUserAsync();
        Task<ErrorOr<LoginDTO>> LoginAsync(LoginQuery query);
        Task<ErrorOr<Success>> ResetPasswordAsync(User user, string token, string password);
        Task<ErrorOr<Created>> RegisterAsync(RegisterUserCommand command, CancellationToken cancellationToken);
    }
}
