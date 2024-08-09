using AuthService.DbModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Provider;

public class AuthServiceContext : IdentityDbContext
{
    public DbSet<DbUserRefreshToken> DbUserRefreshTokens { get; set; }

    public AuthServiceContext(DbContextOptions<AuthServiceContext> options) : base(options)
    {
        
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.HasDefaultSchema("Identity");

        builder.Entity<DbUserRefreshToken>(ent =>
        {
            ent.ToTable("RefreshTokens");

            ent.HasKey(x => x.UserId);
        });

        builder.Entity<IdentityUser>(entity =>
        {
            entity.ToTable(name: "User");
        });

        builder.Entity<IdentityRole>(entity =>
        {
            entity.ToTable(name: "Role");
        });

        builder.Entity<IdentityUserRole<string>>(entity =>
        {
            entity.ToTable("UserRoles");
        });

        builder.Entity<IdentityUserClaim<string>>(entity =>
        {
            entity.ToTable("UserClaims");
        });

        builder.Entity<IdentityUserLogin<string>>(entity =>
        {
            entity.ToTable("UserLogins");

            entity.HasKey(x => x.UserId);
        });

        builder.Entity<IdentityRoleClaim<string>>(entity =>
        {
            entity.ToTable("RoleClaims");
        });

        builder.Entity<IdentityUserToken<string>>(entity =>
        {
            entity.ToTable("UserTokens");
        });
    }
}
