using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using RestApi.Application.Models;
using RestApi.Application.V1.Aggregates.Users.Commands;
using RestApi.Application.V1.Aggregates.Users.DTOs;
using RestApi.Application.V1.Aggregates.Users.Queries;
using RestApi.Application.V1.Configuration;
using RestApi.Application.V1.Services;
using RestApi.Application.V1.Shared;
using RestApi.Domain.V1.Aggregates.Users.Entities;
using RestApi.Domain.V1.Aggregates.Users.Repositories;
using RestApi.Identity.Configuration;
using System.Security.Claims;

namespace RestApi.Identity.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly IUserRepository _userRepository;
        private readonly JwtOptions _jwtOptions;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IMailService _mailService;

        public IdentityService(IUserRepository userRepository, IOptions<JwtOptions> jwtOptions, IHttpContextAccessor httpContextAccessor, IMailService mailService)
        {
            _userRepository = userRepository;
            _jwtOptions = jwtOptions.Value;
            _httpContextAccessor = httpContextAccessor;
            _mailService = mailService;
        }

        private async Task SendVerificationEmailAsync(RestApiUser user, CancellationToken cancellationToken)
        {
            //string token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // replace with new user references

            string token = "123";

            var mailRequest = new MailRequest
            {
                ToEmail = user.Email,
                Subject = "Confirm your email",
                Body = $"Your confirmation token is: {token}"
            };

            await _mailService.SendAsync(mailRequest, cancellationToken);
        }

        public Task<LoggedUserDTO?> GetLoggedUserAsync()
        {
            //if (_httpContextAccessor.HttpContext is not null)
            //{
            //    //var user = await _userManager.GetUserAsync(_httpContextAccessor?.HttpContext?.User);

            //    // replace with new user references

            //    var user = new { Id = new Guid(), Email = "askdjaskda" };

            //    LoggedUserDTO? dto = new LoggedUserDTO
            //    {
            //        Id = user.Id,
            //        Email = user.Email
            //    };

            //    return Task.FromResult(dto);
            //}

            return null;
        }

        public async Task<LoginDTO> LoginAsync(LoginQuery query)
        {
            //var signInResult = await _signInManager.PasswordSignInAsync(query.Email, query.Password, false, true);

            // replace with new user references

            if (true)
            {
                return await GenerateJsonWebTokenAsync(query.Email);
            }

            var result = new LoginDTO();

            //if (signInResult.IsLockedOut)
            //    result.AddError("This account is blocked");

            //else if (signInResult.IsNotAllowed)
            //    result.AddError("This account is not allow to login");

            //else if (signInResult.RequiresTwoFactor)
            //    result.AddError("It is necessary to confirm the login at your second device");

            //else
            //    result.AddError("Invalid credentials");

            return result;
        }

        public async Task<Result> RegisterAsync(RegisterUserCommand command, CancellationToken cancellationToken)
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

            await _userRepository.AddAsync(user, cancellationToken);

            return Result.Create();

            //await SendVerificationEmailAsync(identityUser, cancellationToken);

            //await _userManager.SetLockoutEnabledAsync(identityUser, false);
        }

        private Task<LoginDTO> GenerateJsonWebTokenAsync(string email)
        {
            //var user = await _userManager.FindByEmailAsync(email);

            //var claims = await GetClaimsAsync(user);

            // replace with new user references

            return Task.FromResult(new LoginDTO());

            //var expirationDate = DateTime.Now.AddSeconds(_jwtOptions.ExpirationInSeconds);

            //var jwt = new JwtSecurityToken(
            //    issuer: _jwtOptions.Issuer,
            //    audience: _jwtOptions.Audience,
            //    claims: claims,
            //    notBefore: DateTime.Now,
            //    expires: expirationDate,
            //    signingCredentials: _jwtOptions.SigningCredentials
            //);

            //var token = new JwtSecurityTokenHandler().WriteToken(jwt);

            //return new LoginDTO
            //{
            //    User = new LoggedUserDTO { Id = user.Id, Email = user.Email },
            //    Token = token,
            //    ExpirationDate = expirationDate,
            //};
        }

        private Task<IList<Claim>> GetClaimsAsync(RestApiUser user)
        {
            //var claims = await _userManager.GetClaimsAsync(user);
            //var roles = await _userManager.GetRolesAsync(user);

            // replace with new user references

            //claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()));
            //claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            //claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            //claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, DateTime.Now.ToString()));
            //claims.Add(new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToString()));

            //foreach (var role in roles)
            //{
            //    claims.Add(new Claim("role", role));
            //}

            //return claims;

            IList<Claim> claims = new List<Claim>();

            return Task.FromResult(claims);
        }

        public Task<RestApiUser> FindUserByEmailAsync(string email)
        {
            // replace with new user references
            //return _userManager.FindByEmailAsync(email);
            return Task.FromResult(new RestApiUser());
        }

        public Task<Result> ConfirmEmailAsync(RestApiUser user, string token)
        {
            //var result = await _userManager.ConfirmEmailAsync(user, token);

            //// replace with new user references

            //if (result.Succeeded)
            //{
            return Task.FromResult(Result.Create());
            //}

            //return Result.Create().Error(result.Errors.Select(x => x.Description));
        }

        public async Task<Result> ForgotPasswordAsync(RestApiUser user, CancellationToken cancellationToken)
        {
            //string token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // replace with new user references

            string token = "asdlksadjlksa";

            var mailRequest = new MailRequest
            {
                ToEmail = user.Email,
                Subject = "Reset Password",
                TemplatePath = "ResetPassword.cshtml",
                TemplateModel = new
                {
                    Token = token
                }
            };

            await _mailService.SendAsync(mailRequest, cancellationToken);

            return Result.Create();
        }

        public Task<Result> ResetPasswordAsync(RestApiUser user, string token, string password)
        {
            //var result = await _userManager.ResetPasswordAsync(user, token, password);

            // replace with new user references

            return Task.FromResult(Result.Create());
            //if (result.Succeeded)
            //{
            //    return Result.Create();
            //}

            //return Result.Create().Error(result.Errors.Select(x => x.Description));
        }
    }
}
