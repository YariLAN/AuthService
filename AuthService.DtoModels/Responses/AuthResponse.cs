namespace AuthService.DtoModels.Responses;

public class AuthResponse
{
    public string AccessToken { get; set; }

    public DateTime ExpiresAt { get; set; }
}
