using AuthService.Repositories;
using AuthService.Repositories.Interfaces;
using AuthService.Services;
using AuthService.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AuthService.Extensions
{
    public static class DependencyInjectionExtensions
    {
        public static void InjectServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<JwtOptions>(configuration.GetSection(nameof(JwtOptions)));

            services.AddOptions<JwtBearerOptions>()
                .Configure<IConfiguration>((options, configuration) =>
                {
                    var jwtOptions = configuration.GetSection(nameof(JwtOptions)).Get<JwtOptions>();

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(jwtOptions!.SecretKey))
                    };
                });

            services.AddScoped<IUserService, UserService>();
            services.AddScoped<IUserRefreshTokensRepository, UserRefreshTokensRepository>();
        }
    }
}
