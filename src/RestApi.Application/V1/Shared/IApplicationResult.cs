using System;

namespace RestApi.Application.V1.Shared
{
    public interface IApplicationResult
    {
        IEnumerable<string> Errors { get; }
    }
}
