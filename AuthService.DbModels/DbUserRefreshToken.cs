using Microsoft.AspNet.Identity.EntityFramework;

namespace AuthService.DbModels
{
    public class DbUserRefreshToken
    {
        public Guid UserId { get; set; }

        public string RefreshToken { get; set; } = string.Empty;

        public DateTime Created { get; set; }

        public DateTime Expires { get; set; }
    }
}
