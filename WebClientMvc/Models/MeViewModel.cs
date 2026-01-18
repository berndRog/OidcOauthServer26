namespace WebClientMvc.Models;

public sealed record ClaimItem(string Type, string Value);

public sealed class MeViewModel
{
   public string? UserName { get; set; }
   public string? IdToken { get; set; }
   public string? AccessToken { get; set; }
   public string? RefreshToken { get; set; }
   public string? ExpiresAt { get; set; }
   public List<ClaimItem> Claims { get; set; } = new();
}
