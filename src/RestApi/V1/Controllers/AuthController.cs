using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RestApi.Application.V1.Aggregates.Users.Commands;
using RestApi.Application.V1.Aggregates.Users.Constants;
using RestApi.Application.V1.Aggregates.Users.Queries;
using RestApi.Application.V1.Services;
using RestApi.Application.V1.Shared;

namespace RestApi.V1.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v1/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IIdentityService _identityService;

        public AuthController(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginQuery query)
        {
            var result = await _identityService.LoginAsync(query);

            return result.Match(
                onValue: value => (IActionResult)Ok(value),
                onError: errors => BadRequest(result.Format())
            );
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterUserCommand command, CancellationToken cancellationToken)
        {
            var result = await _identityService.RegisterAsync(command, cancellationToken);

            return result.Match(
                onValue: value => (IActionResult)StatusCode(StatusCodes.Status201Created),
                onError: errors => BadRequest(result.Format())
            );
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordCommand command, CancellationToken cancellationToken)
        {
            var user = await _identityService.FindUserByEmailAsync(command.Email);

            if (user is null)
            {
                return NotFound();
            }

            var result = await _identityService.ForgotPasswordAsync(user, cancellationToken);

            return result.Match(
                onValue: value => (IActionResult)NoContent(),
                onError: errors => BadRequest(result.Format())
            );
        }

        [HttpPatch("confirm-email")]
        [Authorize]
        public async Task<IActionResult> ConfirmEmail(ConfirmEmailCommand command)
        {
            var user = await _identityService.FindUserByEmailAsync(command.Email);

            if (user is null)
            {
                return NotFound();
            }

            var result = await _identityService.ConfirmEmailAsync(user, command.Token);

            return result.Match(
                onValue: value => (IActionResult)NoContent(),
                onError: errors => BadRequest(result.Format())
            );
        }

        [HttpPatch("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordCommand command)
        {
            var user = await _identityService.FindUserByEmailAsync(command.Email);

            if (user is null)
            {
                return NotFound();
            }

            var result = await _identityService.ResetPasswordAsync(user, command.Token, command.Password);

            return result.Match(
                onValue: value => (IActionResult)NoContent(),
                onError: errors => BadRequest(result.Format())
            );
        }

        [HttpGet("profile")]
        [Authorize]
        public async Task<IActionResult> Profile()
        {
            var result = await _identityService.GetLoggedUserAsync();

            return result.Match(
                onValue: value => (IActionResult)Ok(value),
                onError: errors => NotFound()
            );
        }

        [HttpGet("is-admin")]
        [Authorize(Roles = AppRoles.Admin)]
        public IActionResult VerifyAdminUser()
        {
            return NoContent();
        }

        [HttpGet("is-logged")]
        [Authorize]
        public IActionResult VerifyRegularUser()
        {
            return NoContent();
        }
    }
}
