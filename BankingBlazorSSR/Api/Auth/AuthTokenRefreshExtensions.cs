using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

public static class AuthTokenRefreshExtensions {
   
   public static async Task<bool> TryRefreshAccessTokenAsync(
      this HttpContext httpContext,
      IHttpClientFactory httpClientFactory,
      IConfiguration config,
      CancellationToken ct = default
   ) {
      // Read current auth ticket (cookie)
      var auth = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
      if (!auth.Succeeded || auth.Properties is null)
         return false;

      // Read tokens from auth cookie
      var refreshToken = auth.Properties.GetTokenValue("refresh_token");
      var accessToken = auth.Properties.GetTokenValue("access_token");
      var expiresAtRaw = auth.Properties.GetTokenValue("expires_at");

      if (string.IsNullOrWhiteSpace(refreshToken))
         return false;

      // Refresh only if token is missing or expires soon (<= 60s)
      if (!IsExpiringSoon(expiresAtRaw))
         return true;

      // var tokenEndpoint = config["Auth:TokenEndpoint"]; // z.B. https://localhost:5001/connect/token
      // var clientId = config["Auth:ClientId"]!;
      // var clientSecret = config["Auth:ClientSecret"]!;

      var tokenEndpointRaw = config["Auth:TokenEndpoint"];
      if (string.IsNullOrWhiteSpace(tokenEndpointRaw))
         throw new InvalidOperationException("Missing configuration: Auth:TokenEndpoint");
      if (!Uri.TryCreate(tokenEndpointRaw, UriKind.Absolute, out var tokenEndpoint))
         return false; // silent fail
      
      var clientId = config["Auth:ClientId"];
      if (string.IsNullOrWhiteSpace(clientId))
         throw new InvalidOperationException("Missing configuration: Auth:ClientId");

      var clientSecret = config["Auth:ClientSecret"];
      if (string.IsNullOrWhiteSpace(clientSecret))
         throw new InvalidOperationException("Missing configuration: Auth:ClientSecret");
      
      var http = httpClientFactory.CreateClient("AuthServer");

      using var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
      req.Content = new FormUrlEncodedContent(new Dictionary<string, string> {
         ["grant_type"] = "refresh_token",
         ["refresh_token"] = refreshToken,
         ["client_id"] = clientId,
         ["client_secret"] = clientSecret
      });

      using var res = await http.SendAsync(req, ct);
      if (!res.IsSuccessStatusCode)
         return false;

      var payload = await res.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct);
      if (payload is null || string.IsNullOrWhiteSpace(payload.access_token))
         return false;

      // Update tokens in cookie
      var newExpiresAt = DateTimeOffset.UtcNow.AddSeconds(payload.expires_in)
         .ToString("o", CultureInfo.InvariantCulture);

      var tokens = new List<AuthenticationToken> {
         new AuthenticationToken { Name = "access_token", Value = payload.access_token },
         new AuthenticationToken { Name = "expires_at",   Value = newExpiresAt }
      };
      if (!string.IsNullOrWhiteSpace(payload.refresh_token))
         tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = payload.refresh_token });

      auth.Properties.StoreTokens(tokens);

      // Re-issue cookie with updated tokens
      await httpContext.SignInAsync(
         CookieAuthenticationDefaults.AuthenticationScheme,
         auth.Principal!,
         auth.Properties);

      return true;
   }

   private static bool IsExpiringSoon(string? expiresAtRaw) {
      if (string.IsNullOrWhiteSpace(expiresAtRaw))
         return true;

      if (!DateTimeOffset.TryParse(expiresAtRaw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
             out var expiresAt))
         return true;

      return expiresAt <= DateTimeOffset.UtcNow.AddSeconds(60);
   }

   private sealed class TokenResponse {
      public string access_token { get; set; } = "";
      public int expires_in { get; set; }
      public string? refresh_token { get; set; }
      public string token_type { get; set; } = "Bearer";
   }
}