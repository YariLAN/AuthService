using AuthService.Provider;
using AuthService.DbModels;
using AuthService.Repositories.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Repositories;

public class UserRefreshTokensRepository(AuthServiceContext serviceContext) : IUserRefreshTokensRepository
{   
    public async Task<bool> Create(DbUserRefreshToken refreshToken)
    {
        try
        {
            await serviceContext.DbUserRefreshTokens.AddAsync(refreshToken);

            await serviceContext.SaveChangesAsync();

            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<DbUserRefreshToken?> Get(Guid? userId)
    {
        return await serviceContext.DbUserRefreshTokens
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.UserId == userId);
    }
}
