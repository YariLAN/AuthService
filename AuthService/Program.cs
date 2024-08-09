using AuthService.Extensions;
using AuthService.Provider;
using AuthService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthService
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.InjectServices(builder.Configuration);

            builder.Services.AddControllers();
            
            builder.Services.AddEndpointsApiExplorer();

            builder.Services.AddCustomSwaggerGen();

            builder.Services.AddDbContext<AuthServiceContext>(opt => 
                opt.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));


            builder.Services.AddAuthentication(builder.Configuration);

            builder.Services.AddIdentityApiEndpoints<IdentityUser>()
                .AddEntityFrameworkStores<AuthServiceContext>()
                .AddDefaultTokenProviders();
            
            var app = builder.Build();

            app.MapCustomIdentityApi<IdentityUser>();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }


}
