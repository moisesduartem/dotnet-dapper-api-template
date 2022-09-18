using System;

namespace RestApi.Application.V1.Shared
{
    public class ApplicationResult : IApplicationResult
    {
        public bool Success { get; private set; }
        public IEnumerable<string> Errors { get; private set; }

        public ApplicationResult(bool success, IEnumerable<string> errors)
        {
            Success = success;
            Errors = errors;
        }
    }
}
