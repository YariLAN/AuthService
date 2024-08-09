using AuthService.DtoModels.Responses;
using AuthService.Mappers;
using AuthService.Repositories.Interfaces;
using AuthService.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services;

public class UserService : IUserService
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IOptions<JwtOptions> _jwtOptions;
    private readonly IOptions<JwtBearerOptions> _jwtBearerOptions;

    private readonly IUserRefreshTokensRepository _refreshTokenRepository;

    public UserService(
        UserManager<IdentityUser> userManager, 
        SignInManager<IdentityUser> signInManager, 
        IOptions<JwtOptions> jwtOptions,
        IOptions<JwtBearerOptions> jwtBearerOptions,
        IUserRefreshTokensRepository refreshTokenRepository)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtOptions = jwtOptions;
        _jwtBearerOptions = jwtBearerOptions;
        _refreshTokenRepository = refreshTokenRepository;
    }

    public async Task<BaseResponse<AuthResponse>> Login(
        LoginRequest loginRequest, 
        LoginFilter filter,
        HttpContext httpContext)
    {
        var useCookieScheme = (filter.useCookies == true) || (filter.useSessionCookies == true);

        _signInManager.AuthenticationScheme = useCookieScheme
            ? IdentityConstants.ApplicationScheme
            : JwtBearerDefaults.AuthenticationScheme;

        var user = await _userManager.FindByEmailAsync(loginRequest.Email);

        if (user is null || !(await _userManager.CheckPasswordAsync(user, loginRequest.Password)))
        {
            return new()
            {
                Message = "Неверный логин или пароль",
                StatusCode = StatusCodes.Status401Unauthorized
            };
        }
        else if (!httpContext.User.Identity!.IsAuthenticated)
        {
            List<Claim> authClaims = new() {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName!)
            };

            var expiresAt = DateTime.UtcNow.AddMinutes(3);

            var accessToken = CreateAccessToken(authClaims, expiresAt);

            var refreshToken = CreateRefreshToken();

            httpContext.Response.Cookies.Append("refresh", refreshToken);

            await _refreshTokenRepository.Create(
                DbUserRefreshTokenMapper.ToMap(
                    new Guid(user.Id), refreshToken, expiresAt.AddHours(_jwtOptions.Value.ExpiresHours)));

            return new()
            {
                Body = new()
                {
                    AccessToken = accessToken,
                    ExpiresAt = expiresAt
                }
            };
        }

        return new() { StatusCode = StatusCodes.Status401Unauthorized };
    }

    private string CreateRefreshToken()
    {
        var randNumber = new byte[64];

        using var rng = RandomNumberGenerator.Create();

        rng.GetBytes(randNumber);

        return Convert.ToBase64String(randNumber);
    }

    private string CreateAccessToken(IEnumerable<Claim> authClaims, DateTime expiresAt)
    {
        var signingCredentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Value.SecretKey)),
            SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            claims: authClaims,
            signingCredentials: signingCredentials,
            expires: expiresAt);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private ClaimsPrincipal? GetPrincipalFromAccessToken(string accessToken)
    {
        var validateParam = _jwtBearerOptions.Value.TokenValidationParameters.Clone();
        validateParam.ValidateLifetime = false;

        var principal = new JwtSecurityTokenHandler().ValidateToken(accessToken, validateParam, out SecurityToken securityToken);

        var jwtSecurityToken = (securityToken as JwtSecurityToken);
        if (jwtSecurityToken is null ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            return null;
        }

        return principal;
    }

    public async Task<BaseResponse<AuthResponse>> Refresh(HttpContext httpContext)
    {
        var accessToken = httpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
        var refreshToken = httpContext.Request.Cookies["refresh"];

        var principal = GetPrincipalFromAccessToken(accessToken);

        if (principal is null)
        {
            httpContext.Response.StatusCode = StatusCodes.Status403Forbidden;

            return new()
            {
                Message = "Invalid Access Token",
                StatusCode = httpContext.Response.StatusCode
            };
        }

        var id = _userManager.GetUserId(principal);

        var dbRefreshToken = await _refreshTokenRepository.Get(new Guid(id));

        if (!refreshToken!.Equals(dbRefreshToken.RefreshToken))
        {
            httpContext.Response.StatusCode = StatusCodes.Status403Forbidden;
                                                                            
            return new()
            {
                Message = "Invalid Refresh Token",
                StatusCode = httpContext.Response.StatusCode
            };
        }
        else if (dbRefreshToken.Expires < DateTime.UtcNow)
        {
            httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;

            httpContext.Response.Cookies.Delete("refresh");

            return new()
            {
                Message = "Refresh Token expires",
                StatusCode = httpContext.Response.StatusCode
            };
        }

        var expires = DateTime.UtcNow.AddHours(_jwtOptions.Value.ExpiresHours);

        // для accessToken получить пользовательские роли
        var authResponse = new AuthResponse()
        {
            AccessToken = CreateAccessToken(principal.Claims, expires),
            ExpiresAt = expires
        };

        var newRefreshToken = CreateRefreshToken();

        httpContext.Response.Cookies.Append("refresh", newRefreshToken, new() { HttpOnly = true });

        return new()
        {
            Body = authResponse,
            Message = "OK",
            StatusCode = StatusCodes.Status200OK
        };
    }
}
