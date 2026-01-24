namespace WebClientMvc;

public sealed class OidcClientOptions {

   // -------------------------
   // Raw configuration values
   // -------------------------
   public string Authority { get; init; } = default!;
   public string ClientId  { get; init; } = default!;
   public string BaseUrl   { get; init; } = default!;

   public string RedirectPath                 { get; init; } = default!;
   public string SignedOutCallbackPath        { get; init; } = default!;
   public string PostLogoutRedirectPath       { get; init; } = default!;
   public string PostLogoutRedirectFallbackPath { get; init; } = default!;

   public string[] Scopes { get; init; } = Array.Empty<string>();

   // -------------------------
   // Normalized base + paths
   // -------------------------
   private string NormalizedBaseUrl =>
      BaseUrl.Trim().TrimEnd('/');

   private static string NormalizePath(string path) {
      if (string.IsNullOrWhiteSpace(path))
         return "/";
      return "/" + path.Trim().TrimStart('/');
   }

   // -------------------------
   // Derived URIs (single source of truth)
   // -------------------------
   public Uri RedirectUri =>
      new($"{NormalizedBaseUrl}{NormalizePath(RedirectPath)}");

   public Uri SignedOutCallbackUri =>
      new($"{NormalizedBaseUrl}{NormalizePath(SignedOutCallbackPath)}");

   public Uri PostLogoutRedirectUri =>
      new($"{NormalizedBaseUrl}{NormalizePath(PostLogoutRedirectPath)}");

   public Uri PostLogoutRedirectFallbackUri =>
      new($"{NormalizedBaseUrl}{NormalizePath(PostLogoutRedirectFallbackPath)}");
}