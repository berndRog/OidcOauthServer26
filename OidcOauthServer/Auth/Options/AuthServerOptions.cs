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
   public string IssuerUri { get; init; } = "https://localhost:7001/";

   /// <summary>
   /// Derived authority base URL (same as issuer, but as string).
   /// </summary>
   public string AuthorityBaseUrl => EnsureTrailingSlash(IssuerUri);


   
   
   public Uri Issuer => new(EnsureTrailingSlash(IssuerUri));

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

   // Scopes
   // ------------------------------------------------------------------
   public string ScopeApi { get; init; } = "api";

   // Clients
   // ------------------------------------------------------------------
   public ClientOptions BlazorWasm { get; init; } = new() {
      ClientId = "blazor-wasm",
      BaseUrl = "https://localhost:6001",
      RedirectPath = "/authentication/login-callback",
      PostLogoutRedirectPath = "/authentication/logout-callback",
      Type = ClientType.Public
   };

   public ClientOptions WebMvc { get; init; } = new() {
      ClientId = "webclient-mvc",
      BaseUrl = "https://localhost:6002",
      RedirectPath = "/signin-oidc",
      PostLogoutRedirectPath = "/signout-callback-oidc",
      Type = ClientType.Confidential
   };

   public AndroidClientOptions Android { get; init; } = new() {
      ClientId = "android-client",
      BaseUrl = "com.rogallab.oidc:",
      RedirectPath = "/callback",
      PostLogoutRedirectPath = "/logout-callback",
      LoopbackRedirectPath = "http://127.0.0.1:8765/callback",
      Type = ClientType.Public
   };

   public ClientOptions ServiceClient { get; init; } = new() {
      ClientId = "service-client",
      Type = ClientType.Confidential
   };

   // ------------------------------------------------------------------
   // Derived redirect URIs
   // ------------------------------------------------------------------
   public Uri ConfigurationEndpointUri =>
      new(Issuer, ConfigurationEndpointPath);

   public Uri AuthorizationEndpointUri =>
      new(Issuer, AuthorizationEndpointPath);

   public Uri TokenEndpointUri =>
      new(Issuer, TokenEndpointPath);

   public Uri UserInfoEndpointUri =>
      new(Issuer, UserInfoEndpointPath);

   public Uri LogoutEndpointUri =>
      new(Issuer, LogoutEndpointPath);

   public Uri BlazorWasmRedirectUri() =>
      CombineBaseAndPath(BlazorWasm.BaseUrl, BlazorWasm.RedirectPath);

   public Uri BlazorWasmPostLogoutRedirectUri() =>
      CombineBaseAndPath(BlazorWasm.BaseUrl, BlazorWasm.PostLogoutRedirectPath);

   public Uri WebMvcRedirectUri() =>
      CombineBaseAndPath(WebMvc.BaseUrl, WebMvc.RedirectPath);

   public Uri WebMvcPostLogoutRedirectUri() =>
      CombineBaseAndPath(WebMvc.BaseUrl, WebMvc.PostLogoutRedirectPath);
   
   public Uri AndroidRedirectUri() =>
      CombineBaseAndPath(Android.BaseUrl, Android.RedirectPath);

   public Uri AndroidLoopbackRedirectUri() =>
      CombineBaseAndPath(Android.BaseUrl, Android.LoopbackRedirectPath);
   
   public Uri AndroidPostLogoutRedirectUri() =>
      CombineBaseAndPath(Android.BaseUrl, Android.PostLogoutRedirectPath);

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

public sealed class ClientOptions {
   public string ClientId { get; init; } = default!;
   public string BaseUrl { get; init; } = "";
   public string RedirectPath { get; init; } = "";
   public string PostLogoutRedirectPath { get; init; } = "";
   public ClientType Type { get; init; } = ClientType.Public;
}

public sealed class AndroidClientOptions {
   public string ClientId { get; init; } = default!;
   public string BaseUrl { get; init; } = "";
   public string RedirectPath { get; init; } = default!;
   public string PostLogoutRedirectPath { get; init; } = default!;
   public string LoopbackRedirectPath { get; init; } = default!;
   public ClientType Type { get; init; } = ClientType.Public;
}

public static class AuthServerSecretKeys {
   public const string WebMvcClientSecret = "AuthServer:WebMvc:ClientSecret";
   public const string ServiceClientSecret = "AuthServer:ServiceClient:ClientSecret";
}