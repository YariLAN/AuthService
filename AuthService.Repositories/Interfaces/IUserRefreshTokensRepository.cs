using AuthService.DbModels;

namespace AuthService.Repositories.Interfaces;

public interface IUserRefreshTokensRepository
{
    public Task<DbUserRefreshToken> Get(Guid? userId);

    public Task<bool> Create(DbUserRefreshToken refreshToken);
}