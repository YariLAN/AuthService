using AuthService.DtoModels.Responses;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Services.Interfaces;

public interface IUserService
{
    public Task<BaseResponse<AuthResponse>> Login(
        LoginRequest loginRequest, 
        LoginFilter filter,
        HttpContext context);

    public Task<BaseResponse<AuthResponse>> Refresh(HttpContext httpContext);
}

public record class LoginFilter
{
    [FromQuery]
    public bool? useCookies { get; set; }

    [FromQuery]
    public bool? useSessionCookies { get; set; }
}
