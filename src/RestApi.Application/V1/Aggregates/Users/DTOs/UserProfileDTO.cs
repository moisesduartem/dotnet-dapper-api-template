namespace RestApi.Application.V1.Aggregates.Users.DTOs
{
    public class UserProfileDTO
    {
        public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public DateTime Birthdate { get; set; }
    }
}
