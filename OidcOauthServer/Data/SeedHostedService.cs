// using OpenIddict.Abstractions;
// using static OpenIddict.Abstractions.OpenIddictConstants;
//
// namespace OidcOauthServer.Data;
//
// /// <summary>
// /// Seeds demo OpenIddict clients for the course:
// /// - Blazor WASM (public, Code + PKCE)
// /// - Android App (public, Code + PKCE)
// /// - Service client (confidential, client credentials)
// ///
// /// NOTE (OpenIddict 7.2):
// /// - The "openid" scope does NOT require an explicit permission.
// /// </summary>
// public sealed class SeedHostedService : IHostedService {
//    private readonly IServiceProvider _sp;
//
//    public SeedHostedService(IServiceProvider sp) => _sp = sp;
//
//    public async Task StartAsync(CancellationToken ct) {
//       using var scope = _sp.CreateScope();
//       var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
//
//       // ----------------------------
//       // 1) Blazor WASM client (Public + Code + PKCE)
//       // ----------------------------
//       if (await apps.FindByClientIdAsync(AuthServerDefaults.BlazorClientId, ct) is null) {
//          await apps.CreateAsync(new OpenIddictApplicationDescriptor {
//             ClientId = AuthServerDefaults.BlazorClientId,
//             DisplayName = "Blazor WASM",
//             ClientType = ClientTypes.Public,
//
//             RedirectUris = { AuthServerDefaults.BlazorRedirectUri },
//             PostLogoutRedirectUris = { AuthServerDefaults.BlazorPostLogoutRedirectUri },
//
//             Permissions = {
//                Permissions.Endpoints.Authorization,
//                Permissions.Endpoints.Token,
//                Permissions.Endpoints.EndSession,
//
//                Permissions.GrantTypes.AuthorizationCode,
//                Permissions.ResponseTypes.Code,
//
//                // "openid" needs no explicit permission in OpenIddict 7.2.
//                // Allow optional standard scopes if you want them:
//                Permissions.Scopes.Profile,
//                // Permissions.Scopes.Email,
//
//                // API scope
//                Permissions.Prefixes.Scope + AuthServerDefaults.ScopeApi
//             }
//          }, ct);
//       }
//
//       // ----------------------------
//       // 2) WebClient MVC (Confidential + Code)
//       // ----------------------------
//       if (await apps.FindByClientIdAsync(AuthServerDefaults.WebClientMvcClientId, ct) is null) {
//          await apps.CreateAsync(new OpenIddictApplicationDescriptor {
//             ClientId = AuthServerDefaults.WebClientMvcClientId,
//             ClientSecret = AuthServerDefaults.WebClientMvcClientSecret,
//             DisplayName = "WebClient MVC (Test)",
//             ClientType = ClientTypes.Confidential,
//
//             RedirectUris = { AuthServerDefaults.WebClientMvcRedirectUri },
//             PostLogoutRedirectUris = { AuthServerDefaults.WebClientMvcPostLogoutRedirectUri },
//
//             Permissions = {
//                Permissions.Endpoints.Authorization,
//                Permissions.Endpoints.Token,
//                Permissions.Endpoints.EndSession,
//
//                Permissions.GrantTypes.AuthorizationCode,
//                Permissions.ResponseTypes.Code,
//
//                // optional standard scopes:
//                Permissions.Scopes.Profile,
//
//                // API scope
//                Permissions.Prefixes.Scope + AuthServerDefaults.ScopeApi
//             }
//          }, ct);
//       }
//
//       // ----------------------------
//       // 3) Android client (Public + Code + PKCE)
//       // ----------------------------
//       if (await apps.FindByClientIdAsync(AuthServerDefaults.AndroidClientId, ct) is null) {
//          await apps.CreateAsync(new OpenIddictApplicationDescriptor {
//             ClientId = AuthServerDefaults.AndroidClientId,
//             DisplayName = "Android App",
//             ClientType = ClientTypes.Public,
//
//             RedirectUris = { AuthServerDefaults.AndroidCustomSchemeRedirectUri },
//
//             Permissions = {
//                Permissions.Endpoints.Authorization,
//                Permissions.Endpoints.Token,
//
//                Permissions.GrantTypes.AuthorizationCode,
//                Permissions.ResponseTypes.Code,
//
//                Permissions.Scopes.Profile,
//                Permissions.Prefixes.Scope + AuthServerDefaults.ScopeApi
//             }
//          }, ct);
//       }
//
//       // ----------------------------
//       // 4) Service / WebApi client (Confidential + Client Credentials)
//       // ----------------------------
//       if (await apps.FindByClientIdAsync(AuthServerDefaults.ServiceClientId, ct) is null) {
//          await apps.CreateAsync(new OpenIddictApplicationDescriptor {
//             ClientId = AuthServerDefaults.ServiceClientId,          // service-client
//             ClientSecret = AuthServerDefaults.ServiceClientSecret,
//             DisplayName = "Service Client",
//             ClientType = ClientTypes.Confidential,
//
//             Permissions = {
//                Permissions.Endpoints.Token,
//                Permissions.GrantTypes.ClientCredentials,
//                Permissions.Prefixes.Scope + AuthServerDefaults.ScopeApi
//             }
//          }, ct);
//       }
//    }
//
//    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
// }
//
// /*
// DE:
// - OpenIddict 7.2 hat kein Permissions.Scopes.OpenId.
// - "openid" ist ein spezieller Scope und braucht keine Permission.
// - Trotzdem kann der Client scope=openid profile api anfordern.
// */
//

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcOauthServer.Data;

/// <summary>
/// Seeds demo OpenIddict clients:
/// - Blazor WASM (public, Code + PKCE)
/// - Web MVC (confidential, Code)
/// - Android (public, Code + PKCE)
/// - Service client (confidential, Client Credentials)
///
/// Notes:
/// - In OpenIddict 7.x, "openid" does not require an explicit scope permission.
/// - Client secrets are read from IConfiguration (UserSecrets/Env/KeyVault).
/// </summary>
public sealed class SeedHostedService : IHostedService
{
   private readonly IServiceProvider _sp;
   private readonly IConfiguration _config;

   public SeedHostedService(IServiceProvider sp, IConfiguration config)
   {
      _sp = sp;
      _config = config;
   }

   public async Task StartAsync(CancellationToken ct)
   {
      using var scope = _sp.CreateScope();

      var options = scope.ServiceProvider.GetRequiredService<IOptions<AuthServerOptions>>().Value;
      var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

      // ------------------------------------------------------------
      // 1) Blazor WASM (Public + Code + PKCE)
      // ------------------------------------------------------------
      if (await apps.FindByClientIdAsync(options.BlazorWasm.ClientId, ct) is null)
      {
         await apps.CreateAsync(new OpenIddictApplicationDescriptor
         {
            ClientId = options.BlazorWasm.ClientId,
            DisplayName = "Blazor WASM",
            ClientType = ClientTypes.Public,

            RedirectUris = { options.GetBlazorWasmRedirectUri() },
            PostLogoutRedirectUris = { options.GetBlazorWasmPostLogoutRedirectUri() },

            Permissions =
            {
               Permissions.Endpoints.Authorization,
               Permissions.Endpoints.Token,
               Permissions.Endpoints.EndSession,

               Permissions.GrantTypes.AuthorizationCode,
               Permissions.ResponseTypes.Code,

               Permissions.Scopes.Profile,
               Permissions.Prefixes.Scope + options.ScopeApi
            },

            Requirements =
            {
               Requirements.Features.ProofKeyForCodeExchange
            }
         }, ct);
      }

      // ------------------------------------------------------------
      // 2) Web MVC (Confidential + Code)
      // ------------------------------------------------------------
      if (await apps.FindByClientIdAsync(options.WebMvc.ClientId, ct) is null)
      {
         var webMvcSecret = _config[AuthServerSecretKeys.WebMvcClientSecret];
         if (string.IsNullOrWhiteSpace(webMvcSecret))
            throw new InvalidOperationException(
               $"Missing secret '{AuthServerSecretKeys.WebMvcClientSecret}'. " +
               "Set it via user-secrets or environment variables.");

         await apps.CreateAsync(new OpenIddictApplicationDescriptor
         {
            ClientId = options.WebMvc.ClientId,
            ClientSecret = webMvcSecret,
            DisplayName = "WebClient MVC",
            ClientType = ClientTypes.Confidential,

            RedirectUris = { options.GetWebMvcRedirectUri() },
            PostLogoutRedirectUris = { options.GetWebMvcPostLogoutRedirectUri() },

            Permissions =
            {
               Permissions.Endpoints.Authorization,
               Permissions.Endpoints.Token,
               Permissions.Endpoints.EndSession,

               Permissions.GrantTypes.AuthorizationCode,
               Permissions.ResponseTypes.Code,

               Permissions.Prefixes.Scope + "openid",
               Permissions.Scopes.Profile,
               Permissions.Prefixes.Scope + options.ScopeApi
            }
         }, ct);
      }

      // ------------------------------------------------------------
      // 3) Android (Public + Code + PKCE)
      // ------------------------------------------------------------
      if (await apps.FindByClientIdAsync(options.Android.ClientId, ct) is null)
      {
         await apps.CreateAsync(new OpenIddictApplicationDescriptor
         {
            ClientId = options.Android.ClientId,
            DisplayName = "Android App",
            ClientType = ClientTypes.Public,

            RedirectUris =
            {
               new Uri(options.Android.CustomSchemeRedirectUri),
               new Uri(options.Android.LoopbackRedirectUri)
            },

            Permissions =
            {
               Permissions.Endpoints.Authorization,
               Permissions.Endpoints.Token,

               Permissions.GrantTypes.AuthorizationCode,
               Permissions.ResponseTypes.Code,

               Permissions.Scopes.Profile,
               Permissions.Prefixes.Scope + options.ScopeApi
            },

            Requirements =
            {
               Requirements.Features.ProofKeyForCodeExchange
            }
         }, ct);
      }

      // ------------------------------------------------------------
      // 4) Service / WebApi (Confidential + Client Credentials)
      // ------------------------------------------------------------
      if (await apps.FindByClientIdAsync(options.ServiceClient.ClientId, ct) is null)
      {
         var serviceSecret = _config[AuthServerSecretKeys.ServiceClientSecret];
         if (string.IsNullOrWhiteSpace(serviceSecret))
            throw new InvalidOperationException(
               $"Missing secret '{AuthServerSecretKeys.ServiceClientSecret}'. " +
               "Set it via user-secrets or environment variables.");

         await apps.CreateAsync(new OpenIddictApplicationDescriptor
         {
            ClientId = options.ServiceClient.ClientId,
            ClientSecret = serviceSecret,
            DisplayName = "Service Client",
            ClientType = ClientTypes.Confidential,

            Permissions =
            {
               Permissions.Endpoints.Token,
               Permissions.GrantTypes.ClientCredentials,
               Permissions.Prefixes.Scope + options.ScopeApi
            }
         }, ct);
      }
   }

   public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
