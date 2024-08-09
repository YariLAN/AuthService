using AuthService.DbModels;
using Microsoft.AspNet.Identity.EntityFramework;

namespace AuthService.Mappers
{
    public static class DbUserRefreshTokenMapper
    {
        public static DbUserRefreshToken ToMap(Guid userId, string refreshToken, DateTime expiresAt)
        {
            return new()
            {
                RefreshToken = refreshToken,
                UserId = userId,
                Expires = expiresAt,
                Created = DateTime.UtcNow
            };
        }
    }
}
