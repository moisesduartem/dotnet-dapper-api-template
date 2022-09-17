using AutoMapper;
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
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

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

        public async Task<UserProfileDTO?> GetLoggedUserAsync()
        {
            if (_httpContextAccessor.HttpContext is not null)
            {
                var claimsPrincipal = _httpContextAccessor?.HttpContext?.User;

                string? userId = 
                    claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);


                var user = await _userRepository.FindByIdAsync(userId);

                if (user is null)
                {
                    return null;
                }

                return _mapper.Map<UserProfileDTO>(user);
            }

            return null;
        }

        public async Task<LoginDTO> LoginAsync(LoginQuery query)
        {
            var hasher = new PasswordHasher<User?>();

            var user = await _userRepository.FindByEmailAsync(query.Email);

            if (user is null)
            {
                var result = new LoginDTO();
                
                result.AddError("Invalid Credentials");
                
                return result;
            }

            var hashVerification = 
                hasher.VerifyHashedPassword(user, user.PasswordHash, query.Password);

            if (hashVerification is not PasswordVerificationResult.Success)
            {
                var result = new LoginDTO();

                result.AddError("Invalid Credentials");

                return result;
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
