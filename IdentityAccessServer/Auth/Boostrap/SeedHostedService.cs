using IdentityAccessServer.Auth.Options;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityAccessServer.Auth.Seeding;

/// <summary>
/// Seeds demo OpenIddict data (idempotent):
/// - API scopes (scope -> resource mapping)
/// - Client registrations (Blazor WASM, Web MVC, Android, Service)
///
/// IMPORTANT:
/// - Resources/Audiences are derived from the *scope definitions* (OpenIddict scopes).
/// - Therefore we seed scopes with Resources={...} and we do NOT need a global "api" scope anymore.
/// </summary>
public sealed class SeedHostedService(
   IServiceProvider sp,
   IConfiguration config,
   ILogger<SeedHostedService> logger
) : IHostedService {

   public async Task StartAsync(CancellationToken ct) {

      using var scope = sp.CreateScope();

      var options = scope.ServiceProvider
         .GetRequiredService<IOptions<AuthServerOptions>>().Value;

      var apps = scope.ServiceProvider
         .GetRequiredService<IOpenIddictApplicationManager>();

      var scopes = scope.ServiceProvider
         .GetRequiredService<IOpenIddictScopeManager>();

      // ------------------------------------------------------------
      // Local helper: Create OR Update (idempotent)
      // ------------------------------------------------------------
      async Task UpsertAsync(OpenIddictApplicationDescriptor descriptor, bool requiresSecret) {
         var existing = await apps.FindByClientIdAsync(descriptor.ClientId!, ct);

         if (existing is null) {
            if (requiresSecret && string.IsNullOrWhiteSpace(descriptor.ClientSecret))
               throw new InvalidOperationException(
                  $"Client '{descriptor.ClientId}' is confidential but no ClientSecret was provided. " +
                  $"Set it via '{AuthServerSecretKeys.WebMvcClientSecret}' / '{AuthServerSecretKeys.ServiceClientSecret}'.");

            await apps.CreateAsync(descriptor, ct);
            logger.LogInformation("Created OpenIddict client: {ClientId}", descriptor.ClientId);
            return;
         }

         if (requiresSecret && string.IsNullOrWhiteSpace(descriptor.ClientSecret))
            throw new InvalidOperationException(
               $"Client '{descriptor.ClientId}' exists and is confidential but no ClientSecret was provided. " +
               $"Set it via configuration (user-secrets / env vars).");

         await apps.UpdateAsync(existing, descriptor, ct);
         logger.LogInformation("Updated OpenIddict client: {ClientId}", descriptor.ClientId);
      }

      // ------------------------------------------------------------
      // Local helper: Seed scopes (idempotent)
      // ------------------------------------------------------------
      async Task UpsertScopeAsync(string scopeName, string resourceName, string displayName) {
         var existing = await scopes.FindByNameAsync(scopeName, ct);

         // Scope -> Resource mapping (THIS is what drives aud/resources in tokens)
         var descriptor = new OpenIddictScopeDescriptor {
            Name = scopeName,
            DisplayName = displayName,
            Resources = { resourceName }
         };

         if (existing is null) {
            await scopes.CreateAsync(descriptor, ct);
            logger.LogInformation("Created OpenIddict scope: {Scope} -> {Resource}", scopeName, resourceName);
            return;
         }

         await scopes.UpdateAsync(existing, descriptor, ct);
         logger.LogInformation("Updated OpenIddict scope: {Scope} -> {Resource}", scopeName, resourceName);
      }

      // ------------------------------------------------------------
      // Local helper: Add API scopes to a client descriptor
      //
      // NOTE:
      // - OpenIddict application permissions decide which scopes a client is allowed to request.
      // - The actual aud/resources are derived later from the scope definitions (above).
      // ------------------------------------------------------------
      void AddApiScopes(OpenIddictApplicationDescriptor d, params string[] apiKeys) {
         foreach (var key in apiKeys) {
            if (!options.Apis.TryGetValue(key, out var api))
               throw new InvalidOperationException(
                  $"AuthServerOptions.Apis does not contain key '{key}'. " +
                  $"Check appsettings: AuthServer:Apis:{key}");

            d.Permissions.Add(Permissions.Prefixes.Scope + api.Scope);
         }
      }

      // ------------------------------------------------------------
      // 0) Seed API scopes (Scope -> Resource)
      // ------------------------------------------------------------
      if (options.Apis.Count == 0)
         throw new InvalidOperationException(
            "No APIs configured. Add AuthServer:Apis:{...} in appsettings.json.");

      foreach (var (key, api) in options.Apis) {
         // key = "CarRentalApi", api.Scope="carrental_api", api.Resource="carrental-api"
         if (string.IsNullOrWhiteSpace(api.Scope) || string.IsNullOrWhiteSpace(api.Resource))
            throw new InvalidOperationException(
               $"Invalid API config for '{key}'. Scope and Resource are required.");

         await UpsertScopeAsync(api.Scope, api.Resource, displayName: key);
      }

      // ------------------------------------------------------------
      // 1) Blazor WASM (Public + Code + PKCE)
      // ------------------------------------------------------------
      var blazor = new OpenIddictApplicationDescriptor {
         ClientId = options.BlazorWasm.ClientId,
         DisplayName = "Blazor WASM",
         ClientType = ClientTypes.Public,

         RedirectUris = { options.BlazorWasmSignInCallbackUri() },
         PostLogoutRedirectUris = { options.BlazorWasmSignOutCallbackUri() },
         
         Permissions = {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,

            Permissions.GrantTypes.AuthorizationCode,
            Permissions.ResponseTypes.Code,

            Permissions.Prefixes.Scope + Scopes.OpenId,
            Permissions.Prefixes.Scope + Scopes.Profile
         },

         Requirements = {
            Requirements.Features.ProofKeyForCodeExchange
         }
      }; 

      // Choose which APIs Blazor may call:
      AddApiScopes(blazor, "BankingApi"); // add more if needed
      AddApiScopes(blazor, "CarRentalApi"); // add more if needed
      
      // Blazor WASM may use refresh tokens (with PKCE + Authorization Code)
      AllowRefreshTokens(blazor); 
      
      await UpsertAsync(blazor, requiresSecret: false);

      // ------------------------------------------------------------
      // 2) Web MVC (Confidential + Code)
      // ------------------------------------------------------------
      var webMvc = new OpenIddictApplicationDescriptor {
         ClientId = options.WebMvc.ClientId,
         ClientSecret = config[AuthServerSecretKeys.WebMvcClientSecret],
         DisplayName = "WebClient MVC",
         ClientType = ClientTypes.Confidential,

         RedirectUris = { options.WebMvcSignInCallbackUri() },
         PostLogoutRedirectUris = { options.WebMvcSignOutCallbackUri() },
         
         Permissions = {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,

            Permissions.GrantTypes.AuthorizationCode,
            Permissions.ResponseTypes.Code,

            Permissions.Prefixes.Scope + Scopes.OpenId,
            Permissions.Prefixes.Scope + Scopes.Profile
         }
      };
      
      AddApiScopes(webMvc, "BankingApi");
      AddApiScopes(webMvc, "CarRentalApi");
      
      AllowRefreshTokens(webMvc); // optional, but common for server-side apps

      await UpsertAsync(webMvc, requiresSecret: true);

      // ------------------------------------------------------------
      // 3) Web BlazorSSR (Confidential + Code)
      // ------------------------------------------------------------
      var webBlazorSsr = new OpenIddictApplicationDescriptor {
         ClientId = options.WebBlazorSsr.ClientId,
         ClientSecret = config[AuthServerSecretKeys.WebBlazorSsrSecret],
         DisplayName = "WebClient Blazor SSR",
         ClientType = ClientTypes.Confidential,

         RedirectUris = { options.WebBlazorSsrSignInCallbackUri() },
         PostLogoutRedirectUris = { options.WebBlazorSsrSignOutCallbackUri() },

         Permissions = {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,

            Permissions.GrantTypes.AuthorizationCode,
            Permissions.ResponseTypes.Code,

            Permissions.Prefixes.Scope + Scopes.OpenId,
            Permissions.Prefixes.Scope + Scopes.Profile
         }
      };

      AddApiScopes(webBlazorSsr, "BankingApi");
      AddApiScopes(webBlazorSsr, "CarRentalApi");
      
      AllowRefreshTokens(webBlazorSsr); 

      await UpsertAsync(webBlazorSsr, requiresSecret: true);
      
      // ------------------------------------------------------------
      // 4) Android (Public + Code + PKCE)
      // ------------------------------------------------------------
      var android = new OpenIddictApplicationDescriptor {
         ClientId = options.Android.ClientId,
         DisplayName = "Android App",
         ClientType = ClientTypes.Public,

         RedirectUris = {
            options.AndroidCustomSchemeRedirectUri(),
            options.AndroidLoopbackRedirectUri()
         },
         PostLogoutRedirectUris = {
            options.AndroidPostLogoutRedirectUri()
         },

         Permissions = {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,

            Permissions.GrantTypes.AuthorizationCode,
            Permissions.ResponseTypes.Code,

            Permissions.Prefixes.Scope + Scopes.OpenId,
            Permissions.Prefixes.Scope + Scopes.Profile
         },

         Requirements = {
            Requirements.Features.ProofKeyForCodeExchange
         }
      };

      AddApiScopes(android, "BankingApi"); 
      AddApiScopes(android, "CarRentalApi"); 
      
      AllowRefreshTokens(android); // optional, but common for mobile apps

      await UpsertAsync(android, requiresSecret: false);

      // ------------------------------------------------------------
      // 5) Service Client (Confidential + Client Credentials)
      // ------------------------------------------------------------
      var service = new OpenIddictApplicationDescriptor {
         ClientId = options.ServiceClient.ClientId,
         ClientSecret = config[AuthServerSecretKeys.ServiceClientSecret],
         DisplayName = "Service Client",
         ClientType = ClientTypes.Confidential,

         Permissions = {
            Permissions.Endpoints.Token,
            Permissions.GrantTypes.ClientCredentials
         }
      };

      // Service client may call multiple APIs:
      AddApiScopes(service, "CarRentalApi", "BankingApi", "ImagesApi");

      await UpsertAsync(service, requiresSecret: true);
   }

   public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
   
   private void AllowRefreshTokens(OpenIddictApplicationDescriptor descriptor) {
      descriptor.Permissions
         .Add(Permissions.GrantTypes.RefreshToken);
      descriptor.Permissions
         .Add(Permissions.Prefixes.Scope + Scopes.OfflineAccess);
   }
}

/*
==========================================================
DIDAKTIK / LERNZIELE (DE)
==========================================================

1) Warum seedet man Scopes UND Clients?
--------------------------------------
OpenIddict trennt klar:
- Scopes: "Welche Berechtigungsbereiche gibt es?" (z.B. carrental_api)
- Resources: "Für welche API gilt der Scope?" (z.B. carrental-api)
- Clients:  "Welche App darf welche Scopes anfordern?"

Der Seed sorgt dafür, dass diese Regeln automatisch und reproduzierbar
in der Datenbank stehen – ohne manuelle Klickarbeit.

2) Scope -> Resource ist der Schlüssel für 'aud'
------------------------------------------------
Die Audience (aud) in Access Tokens entsteht aus den Resources.
Und Resources kommen hier aus den OpenIddictScopeDescriptor.Resources.

Merksatz:
- Client fordert Scope an
- Scope ist mit Resource verknüpft
- Resource wird zu 'aud' im Token

3) Warum KEIN globales 'api' mehr?
----------------------------------
Ein globales "api" wird schnell zur Blackbox:
- Welche API ist gemeint?
- Welche Audience soll geprüft werden?
- Wie trennt man Banking vs CarRental?

Mit pro-API Scopes bleibt das Modell klar:
- carrental_api -> carrental-api
- banking_api   -> banking-api
- images_api    -> images-api

4) Idempotenz (Create OR Update)
--------------------------------
Wir können den Seed bei jedem Start ausführen:
- existiert der Client/Scope -> Update
- existiert er nicht         -> Create

Damit bleibt die Demo stabil, auch wenn sich Konfigurationen ändern
(z.B. RedirectUris, neue Scopes, neue Clients).

5) Minimalprinzip
-----------------
Wir geben Clients nur die Scopes, die sie wirklich brauchen.
Das ist eine konkrete Umsetzung von "Least Privilege".

==========================================================
*/
