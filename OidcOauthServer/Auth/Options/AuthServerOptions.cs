namespace OidcOauthServer.Auth.Options;

/// <summary>
/// Strongly typed configuration for OAuth2/OIDC/OpenIddict demo setup.
///
/// - No secrets in code.
/// - Issuer is the single source of truth (OIDC relevant).
/// - Client secrets are read from configuration (UserSecrets/Env/KeyVault).
/// </summary>
public sealed class AuthServerOptions {
   
   public const string SectionName = "AuthServer";

   // OIDC Issuer (single source of truth)
   // ------------------------------------------------------------------
   /// <summary>
   /// OIDC issuer URI (must end with slash).
   /// Example: https://localhost:7001/
   /// </summary>
   public string IssuerUri { get; init; } = string.Empty;

   /// <summary>
   /// Derived authority base URL (same as issuer, but as string).
   /// </summary>
   public string AuthorityBaseUrl => EnsureTrailingSlash(IssuerUri);
   
   public Uri Issuer => new(EnsureTrailingSlash(IssuerUri));
   
   // Token behavior (dev/teaching vs realistic production setup)
   // ------------------------------------------------------------------
   /// <summary>
   /// Token-related switches (kept together to avoid option-sprawl).
   /// </summary>
   public TokenOptions Tokens { get; init; } = new();

   // Endpoints (paths are stable; actual URIs derived from Issuer)
   // ------------------------------------------------------------------
   // OIDC-standardized well-known prefix (MUST be root-level)
   public const string WellKnownPrefix = ".well-known";
   public const string ConfigurationEndpointPath =
      WellKnownPrefix + "/openid-configuration";

   // OpenIddict protocol endpoints
   public const string ConnectPrefix = "connect";
   public const string AuthorizationEndpointPath = ConnectPrefix + "/authorize";
   public const string TokenEndpointPath = ConnectPrefix + "/token";
   public const string UserInfoEndpointPath = ConnectPrefix + "/userinfo";
   public const string LogoutEndpointPath = ConnectPrefix + "/logout";

   // APIs (Resources + Scopes)
   // ------------------------------------------------------------------
   public Dictionary<string, ApiOptions> Apis { get; init; } = new();
   
   // Convenience accessors for known APIs
   // ----------------------------------------------------------------
   public ApiOptions CarRentalApi => Apis["CarRentalApi"];
   public ApiOptions BankingApi   => Apis["BankingApi"];
   public ApiOptions ImagesApi    => Apis["ImagesApi"];
   
   // Clients
   // ------------------------------------------------------------------
   public ClientOptions BlazorWasm { get; init; } = default!;
   public ClientOptions WebMvc { get; init; } = default!;
   public AndroidClientOptions Android { get; init; } = default!;
   public ClientOptions ServiceClient { get; init; } = default!;
   
   // Derived redirect URIs
   // ------------------------------------------------------------------
   public Uri ConfigurationEndpointUri => new(Issuer, ConfigurationEndpointPath);
   public Uri AuthorizationEndpointUri => new(Issuer, AuthorizationEndpointPath);
   public Uri TokenEndpointUri => new(Issuer, TokenEndpointPath);
   public Uri UserInfoEndpointUri => new(Issuer, UserInfoEndpointPath);
   public Uri LogoutEndpointUri => new(Issuer, LogoutEndpointPath);
   
   public Uri BlazorWasmRedirectUri() =>
      CombineBaseAndPath(BlazorWasm.BaseUrl, BlazorWasm.RedirectPath);
   public Uri BlazorWasmPostLogoutRedirectUri() =>
      CombineBaseAndPath(BlazorWasm.BaseUrl, BlazorWasm.PostLogoutRedirectPath);

   public Uri WebMvcRedirectUri() =>
      CombineBaseAndPath(WebMvc.BaseUrl, WebMvc.RedirectPath);
   public Uri WebMvcPostLogoutRedirectUri() =>
      CombineBaseAndPath(WebMvc.BaseUrl, WebMvc.PostLogoutRedirectPath);
   
   public Uri AndroidCustomSchemeRedirectUri() =>
      new (Android.CustomSchemeRedirectUriString, UriKind.Absolute);
   public Uri AndroidLoopbackRedirectUri() =>
      new (Android.LoopbackRedirectUriString, UriKind.Absolute);
   
   public Uri AndroidPostLogoutRedirectUri()
      => new(Android.PostLogoutRedirectUriString, UriKind.Absolute);
   
   // ------------------------------------------------------------------
   // Helpers
   // ------------------------------------------------------------------
   public static string EnsureTrailingSlash(string url)
      => url.EndsWith("/", StringComparison.Ordinal) ? url : url + "/";

   public static Uri CombineBaseAndPath(string baseUrl, string path)
      => new Uri($"{baseUrl.TrimEnd('/')}{(path.StartsWith('/') ? "" : "/")}{path}");
}

public enum ClientType {
   Public = 1,
   Confidential = 2
}

public static class AuthServerSecretKeys {
   public const string WebMvcClientSecret = "AuthServer:WebMvc:ClientSecret";
   public const string ServiceClientSecret = "AuthServer:ServiceClient:ClientSecret";
}