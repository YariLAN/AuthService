using AuthService.DtoModels.Responses;
using AuthService.Services.Interfaces;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("")]
    public class AuthServiceController(IUserService userService) : ControllerBase
    {
        [HttpPost("/login")]
        public async Task<BaseResponse<AuthResponse>> Login(
            [FromBody] LoginRequest loginRequest,
            LoginFilter filter)
        {
            return await userService.Login(loginRequest, filter, HttpContext);
        }

        [HttpPost("/refresh")]
        public async Task<BaseResponse<AuthResponse>> Refresh()
        {
            return await userService.Refresh(HttpContext);
        }
    }
}
