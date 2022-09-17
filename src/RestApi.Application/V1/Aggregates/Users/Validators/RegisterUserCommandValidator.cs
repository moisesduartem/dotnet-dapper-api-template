using FluentValidation;
using RestApi.Application.V1.Aggregates.Users.Commands;

namespace RestApi.Application.V1.Aggregates.Users.Validators
{
    public class RegisterUserCommandValidator : AbstractValidator<RegisterUserCommand>
    {
        public RegisterUserCommandValidator()
        {
            RuleFor(x => x.Email).NotEmpty()
                                 .EmailAddress()
                                 .MinimumLength(7)
                                 .MaximumLength(60);

            RuleFor(x => x.Password).NotEmpty()
                                    .MinimumLength(6);

            RuleFor(x => x.PasswordConfirmation).Equal(x => x.Password);

            RuleFor(x => x.FirstName).NotEmpty()
                                     .MinimumLength(3)
                                     .MaximumLength(18);

            RuleFor(x => x.LastName).NotEmpty()
                                    .MinimumLength(3)
                                    .MaximumLength(25);

            RuleFor(x => x.Birthdate).NotEmpty()
                                       .Matches(@"^([0-9]){4}(-)([0-9]){2}(-)([0-9]){2}$")
                                       .Length(10);
        }
    }
}
