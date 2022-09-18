using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RestApi.Application.V1.Aggregates.Users.Commands;
using RestApi.Application.V1.Aggregates.Users.DTOs;
using RestApi.Application.V1.Aggregates.Users.Queries;
using RestApi.Application.V1.Configuration;
using RestApi.Application.V1.Services;
using RestApi.Domain.V1.Aggregates.Users.Entities;
using RestApi.Domain.V1.Aggregates.Users.Repositories;
using RestApi.Identity.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ErrorOr;

namespace RestApi.Identity.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly IUserRepository _userRepository;
        private readonly JwtOptions _jwtOptions;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IMailService _mailService;
        private readonly IMapper _mapper;

        public IdentityService(IUserRepository userRepository, IOptions<JwtOptions> jwtOptions, IHttpContextAccessor httpContextAccessor, IMailService mailService, IMapper mapper)
        {
            _userRepository = userRepository;
            _jwtOptions = jwtOptions.Value;
            _httpContextAccessor = httpContextAccessor;
            _mailService = mailService;
            _mapper = mapper;
        }

        private string GenerateRandomToken()
        {
            string content = $"{DateTime.Now}_{Guid.NewGuid()}";
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(content));
        }

        private async Task SendVerificationEmailAsync(User user, CancellationToken cancellationToken)
        {
            var mailRequest = new MailRequest
            {
                ToEmail = user.Email,
                Subject = "Confirm your email",
                Body = $"Your confirmation token is: {user.EmailConfirmationCode}"
            };

            await _mailService.SendAsync(mailRequest, cancellationToken);
        }

        public async Task<ErrorOr<UserProfileDTO>> GetLoggedUserAsync()
        {
            if (_httpContextAccessor.HttpContext is not null)
            {
                var claimsPrincipal = _httpContextAccessor?.HttpContext?.User;

                string? userId =
                    claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);

                var user = await _userRepository.FindByIdAsync(userId);

                if (user is not null)
                {
                    return _mapper.Map<UserProfileDTO>(user);
                }
            }

            return Error.NotFound();
        }

        public async Task<ErrorOr<LoginDTO>> LoginAsync(LoginQuery query)
        {
            var hasher = new PasswordHasher<User?>();

            var user = await _userRepository.FindByEmailAsync(query.Email, withPassword: true);

            if (user is null)
            {
                return Error.Validation(description: "Invalid Credentials");
            }

            var hashVerification =
                hasher.VerifyHashedPassword(user, user.PasswordHash, query.Password);

            if (hashVerification is not PasswordVerificationResult.Success)
            {
                return Error.Validation(description: "Invalid Credentials");
            }

            var expirationDate = DateTime.Now.AddSeconds(_jwtOptions.ExpirationInSeconds);

            var claims = await GetClaimsAsync(user);

            string token = GenerateJsonWebTokenAsync(claims, expirationDate);

            return new LoginDTO
            {
                User = new LoggedUserDTO { Id = user.Id, Email = user.Email },
                Token = token,
                ExpirationDate = expirationDate,
            };
        }

        public async Task<ErrorOr<Created>> RegisterAsync(RegisterUserCommand command, CancellationToken cancellationToken)
        {
            var hasher = new PasswordHasher<User>();

            var user = new User(
                firstName: command.FirstName,
                lastName: command.LastName,
                email: command.Email,
                birthdate: Convert.ToDateTime(command.Birthdate)
            );

            string hash = hasher.HashPassword(user, command.Password);

            user.SetPassword(hash);

            string emailConfirmationCode = GenerateRandomToken();

            user.ConfigureEmailConfirmation(emailConfirmationCode);

            await _userRepository.AddAsync(user, cancellationToken);

            await SendVerificationEmailAsync(user, cancellationToken);

            return Result.Created;
        }

        private string GenerateJsonWebTokenAsync(IList<Claim> claims, DateTime expirationDate)
        {
            var jwt = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: claims,
                notBefore: DateTime.Now,
                expires: expirationDate,
                signingCredentials: _jwtOptions.SigningCredentials
            );

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private async Task<IList<Claim>> GetClaimsAsync(User user)
        {
            var roles = await _userRepository.GetRolesByUserIdAsync(user.Id);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Nbf, DateTime.Now.ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToString())
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim("role", role));
            }

            return claims;
        }

        public Task<User> FindUserByEmailAsync(string email)
        {
            return _userRepository.FindByEmailAsync(email);
        }

        public async Task<ErrorOr<Success>> ConfirmEmailAsync(User user, string token)
        {
            if (user.EmailConfirmationCode != token)
            {
                return Error.Validation(description: "Invalid token");
            }

            user.ConfirmEmail();

            await _userRepository.ConfirmEmailAsync(user);

            return Result.Success;
        }

        public async Task<ErrorOr<Success>> ForgotPasswordAsync(User user, CancellationToken cancellationToken)
        {
            string resetPasswordCode = GenerateRandomToken();

            user.ConfigureResetPassword(resetPasswordCode);

            await _userRepository.UpdateResetPasswordCodeAsync(user);

            var mailRequest = new MailRequest
            {
                ToEmail = user.Email,
                Subject = "Reset Password",
                TemplatePath = "ResetPassword.cshtml",
                TemplateModel = new
                {
                    Token = resetPasswordCode
                }
            };

            await _mailService.SendAsync(mailRequest, cancellationToken);

            return Result.Success;
        }

        public async Task<ErrorOr<Success>> ResetPasswordAsync(User user, string token, string password)
        {
            bool isExpired = DateTime.Now.CompareTo(user.ResetPasswordExpiration) >= 0;
            bool isCorrect = user.ResetPasswordCode == token;

            if (!isCorrect)
            {
                return Error.Validation(description: "Invalid token");
            }

            if (isExpired)
            {
                return Error.Validation(description: "Expired token");
            }

            user.ClearResetPassword();

            var hasher = new PasswordHasher<User>();

            string hash = hasher.HashPassword(user, password);

            user.SetPassword(hash);

            await _userRepository.UpdatePasswordAsync(user);

            return Result.Success;
        }
    }
}
