using ErrorOr;

namespace RestApi.Application.V1.Shared
{
    public static class ErrorOrExtensions
    {
        public static IApplicationResult Format<T>(this ErrorOr<T> errorOr)
        {
            var errors = errorOr.Errors.Where(x => !string.IsNullOrEmpty(x.Description))
                                       .Select(x => x.Description)
                                       .AsEnumerable();
            
            bool success = errorOr.Errors.Count == 0;

            return new ApplicationResult(success, errors);
        }
    }
}
