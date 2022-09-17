namespace RestApi.Domain.V1.Shared
{
    public abstract class Entity<T> where T : class
    {
        public Guid Id { get; init; }

        protected Entity()
        {
            Id = Guid.NewGuid();
        }
    }
}
