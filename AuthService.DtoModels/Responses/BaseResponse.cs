using Microsoft.AspNetCore.Http;

namespace AuthService.DtoModels.Responses;

public class BaseResponse<T>
{
    public T Body { get; set; }

    public string Message { get; set; } = string.Empty;

    public int StatusCode { get; set; } = StatusCodes.Status200OK;
}
