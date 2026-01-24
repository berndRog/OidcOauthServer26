using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OidcOauthServer.Auth.Claims;
using OidcOauthServer.Auth.Options;
using OidcOauthServer.Infrastructure.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcOauthServer.Auth.Endpoints;

/// <summary>
/// OpenID Connect protocol endpoints:
/// - Authorization (/connect/authorize)
/// - Token issuance (/connect/token)
/// - UserInfo (/connect/userinfo)
///
/// This controller bridges ASP.NET Identity and OpenIddict.
/// </summary>
[ApiController]
public sealed class OidcController(
   UserManager<ApplicationUser> users,
   SignInManager<ApplicationUser> signIn,
   IOptions<AuthServerOptions> authOptions,
   ILogger<OidcController> logger
) : Controller {
   private readonly AuthServerOptions _auth = authOptions.Value;

   // --------------------------------------------------------------------
   // /connect/authorize
   // --------------------------------------------------------------------
   [HttpGet("/" + AuthServerOptions.AuthorizationEndpointPath)]
   public async Task<IActionResult> Authorize(CancellationToken ct) {
      var request = HttpContext.GetOpenIddictServerRequest()
         ?? throw new InvalidOperationException("OpenID Connect request missing.");

      logger.LogInformation(
         "Authorize request: client_id='{ClientId}', redirect_uri='{RedirectUri}', scope='{Scope}', response_type='{ResponseType}'",
         request.ClientId, request.RedirectUri, request.Scope, request.ResponseType
      );

      // Build return URL for post-login continuation
      var returnUrl = Request.PathBase + Request.Path + Request.QueryString;

      // Explicitly authenticate using the Identity application cookie
      var authResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

      if (!authResult.Succeeded) {
         logger.LogInformation(
            "Authorize: no Identity cookie -> challenge, returnUrl='{ReturnUrl}'",
            returnUrl
         );

         return Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme
         );
      }

      // Load domain user
      var user = await users.GetUserAsync(authResult.Principal!);
      if (user is null) {
         logger.LogWarning(
            "Authorize: Identity cookie principal has no user -> challenge, returnUrl='{ReturnUrl}'",
            returnUrl
         );

         return Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme
         );
      }

      // Create principal from ASP.NET Identity
      var principal = await signIn.CreateUserPrincipalAsync(user);
      var identity = (ClaimsIdentity)principal.Identity!;

      // --- Mandatory OIDC subject (sub) -------------------------------------
      var subject =
         principal.FindFirstValue(ClaimTypes.NameIdentifier)
         ?? user.Id;

      principal.SetClaim(AuthClaims.Subject, subject);

      // --- Profile / standard claims ----------------------------------------
      if (!string.IsNullOrWhiteSpace(user.Email))
         identity.AddClaim(new Claim(AuthClaims.Email, user.Email));

      if (!string.IsNullOrWhiteSpace(user.UserName))
         identity.AddClaim(new Claim(AuthClaims.PreferredUsername, user.UserName));

      // --- Domain-specific claims -------------------------------------------
      identity.AddClaim(new Claim(AuthClaims.AccountType, user.AccountType));

      // Admin rights (bitmask enum → int → string)
      identity.AddClaim(new Claim(
         AuthClaims.AdminRights,
         ((int)user.AdminRights).ToString()
      ));

      // Lifecycle timestamps (ISO-8601, stable for all clients)
      identity.AddClaim(new Claim(
         AuthClaims.CreatedAt,
         user.CreatedAt.ToUniversalTime().ToString("O")
      ));

      identity.AddClaim(new Claim(
         AuthClaims.UpdatedAt,
         user.UpdatedAt.ToUniversalTime().ToString("O")
      ));

      // --- Scopes & resources ------------------------------------------------
      // Scopes come from the client request (limited by client permissions).
      // Resources (audiences) are derived from the requested API scopes:
      //   scope=carrental_api -> resource=carrental-api
      //   scope=banking_api   -> resource=banking-api
      //   scope=images_api    -> resource=images-api
      var scopes = request.GetScopes().ToArray();
      principal.SetScopes(scopes);

      var resources = ResolveResourcesFromScopes(scopes);
      principal.SetResources(resources);

      logger.LogInformation(
         "Authorize: user='{UserName}', sub='{Sub}', scopes=[{Scopes}], resources=[{Resources}]",
         user.UserName,
         subject,
         string.Join(", ", scopes),
         string.Join(", ", resources)
      );

      // --- Destinations mapping ---------------------------------------------
      foreach (var claim in principal.Claims)
         claim.SetDestinations(
            ClaimDestinations.GetDestinations(claim, principal)
         );

      return SignIn(
         principal,
         OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
      );
   }

   // --------------------------------------------------------------------
   // /connect/token
   // --------------------------------------------------------------------
   [HttpPost("/" + AuthServerOptions.TokenEndpointPath)]
   public async Task<IActionResult> Token(CancellationToken ct) {
      var request = HttpContext.GetOpenIddictServerRequest()
         ?? throw new InvalidOperationException("OpenID Connect request missing.");

      logger.LogInformation(
         "Token request: grant_type='{GrantType}', client_id='{ClientId}', scope='{Scope}'",
         request.GrantType, request.ClientId, request.Scope
      );

      // --- Authorization Code / Refresh Token flow --------------------------
      if (request.IsAuthorizationCodeGrantType() ||
          request.IsRefreshTokenGrantType()) {
         var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );

         logger.LogInformation(
            "Token: code/refresh -> issuing tokens for client_id='{ClientId}'",
            request.ClientId
         );

         return SignIn(
            result.Principal!,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );
      }

      // --- Client Credentials flow ------------------------------------------
      if (request.IsClientCredentialsGrantType()) {
         logger.LogInformation(
            "Token: client_credentials -> issuing access token for client_id='{ClientId}'",
            request.ClientId
         );

         var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );

         identity.AddClaim(new Claim(AuthClaims.Subject, request.ClientId!));
         identity.AddClaim(new Claim(AuthClaims.AccountType, "service"));

         var principal = new ClaimsPrincipal(identity);

         var scopes = request.GetScopes().ToArray();
         principal.SetScopes(scopes);

         var resources = ResolveResourcesFromScopes(scopes);
         principal.SetResources(resources);

         foreach (var claim in principal.Claims)
            claim.SetDestinations(Destinations.AccessToken);

         logger.LogInformation(
            "Token: client_credentials -> client_id='{ClientId}', scopes=[{Scopes}], resources=[{Resources}]",
            request.ClientId,
            string.Join(", ", scopes),
            string.Join(", ", resources)
         );

         return SignIn(
            principal,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );
      }

      logger.LogWarning("Token: unsupported grant_type '{GrantType}'", request.GrantType);
      return BadRequest(new { error = "unsupported_grant_type" });
   }

   // --------------------------------------------------------------------
   // /connect/userinfo
   // --------------------------------------------------------------------
   [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
   [HttpGet("/" + AuthServerOptions.UserInfoEndpointPath)]
   public IActionResult UserInfo() {
      logger.LogInformation(
         "UserInfo request: sub='{Sub}', azp='{Azp}'",
         User.FindFirst(AuthClaims.Subject)?.Value,
         User.FindFirst("azp")?.Value
      );

      return Ok(new {
         sub = User.FindFirst(AuthClaims.Subject)?.Value,
         preferred_username = User.FindFirst(AuthClaims.PreferredUsername)?.Value,
         email = User.FindFirst(AuthClaims.Email)?.Value,
         account_type = User.FindFirst(AuthClaims.AccountType)?.Value,
         admin_rights = User.FindFirst(AuthClaims.AdminRights)?.Value,
         created_at = User.FindFirst(AuthClaims.CreatedAt)?.Value,
         updated_at = User.FindFirst(AuthClaims.UpdatedAt)?.Value
      });
   }

   // --------------------------------------------------------------------
   // Helpers
   // --------------------------------------------------------------------
   private string[] ResolveResourcesFromScopes(string[] requestedScopes) {
      // Map requested API scopes -> resources/audiences using configuration.
      // Non-API scopes like "openid" or "profile" are ignored here.
      return _auth.Apis.Values
         .Where(api => requestedScopes.Contains(api.Scope, StringComparer.Ordinal))
         .Select(api => api.Resource)
         .Distinct(StringComparer.Ordinal)
         .ToArray();
   }

   /*
   ======================================================================
   DIDAKTIK / LERNZIELE
   ======================================================================

   Ziel dieses Controllers ist es, den vollständigen OAuth2 / OpenID
   Connect Authorization Code Flow mit OpenIddict zu verstehen und
   selbst kontrolliert umzusetzen – ohne Blackbox.

   Lernziele:

   1. Trennung von Verantwortung
      - ASP.NET Identity ist ausschließlich für Login & Benutzerverwaltung
      - OpenIddict ist ausschließlich für Token-Erzeugung und Protokoll
      - Domain-spezifische Informationen (Customer, Employee, Rights)
        werden explizit als Claims modelliert

   2. Bewusste Claim-Modellierung
      - Standard-OIDC-Claims (sub, email, profile)
      - Erweiterung um fachliche Claims (account_type, admin_rights)
      - Keine impliziten Rollenannahmen

   3. Scopes vs. Resources (Audience)
      - Scope  = Berechtigung / Capability (z.B. carrental_api)
      - Resource = Ziel-API / Audience (z.B. carrental-api)
      - Der AuthServer mappt Scope -> Resource über Konfiguration (AuthServer:Apis)

   4. Destinations sind entscheidend
      - Jeder Claim muss explizit einem Token zugewiesen werden
      - ID Token ≠ Access Token
      - Sicherheit entsteht durch bewusste Entscheidung

   5. Ein Server – mehrere Client-Typen
      - Browser (MVC / Blazor)
      - Mobile (Android, PKCE)
      - Services (Client Credentials)
      - Alle nutzen denselben Identity-Kern

   Ergebnis:
   Studierende verstehen, warum moderne Auth-Systeme
   nicht "einfach konfiguriert", sondern bewusst modelliert werden.

   ======================================================================
   */
}

/*using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OidcOauthServer.Auth.Claims;
using OidcOauthServer.Auth.Options;
using OidcOauthServer.Infrastructure.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcOauthServer.Auth.Endpoints;

/// <summary>
/// OpenID Connect protocol endpoints:
/// - Authorization (/connect/authorize)
/// - Token issuance (/connect/token)
/// - UserInfo (/connect/userinfo)
///
/// This controller bridges ASP.NET Identity and OpenIddict.
/// </summary>
[ApiController]
public sealed class OidcController(
   UserManager<ApplicationUser> users,
   SignInManager<ApplicationUser> signIn,
   IOptions<AuthServerOptions> authOptions,
   ILogger<OidcController> logger
) : Controller {
   private readonly AuthServerOptions _auth = authOptions.Value;

   // --------------------------------------------------------------------
   // /connect/authorize
   // --------------------------------------------------------------------
   [HttpGet("/" + AuthServerOptions.AuthorizationEndpointPath)]
   public async Task<IActionResult> Authorize(CancellationToken ct) {
      var request = HttpContext.GetOpenIddictServerRequest()
         ?? throw new InvalidOperationException("OpenID Connect request missing.");

      logger.LogInformation(
         "Authorize request: client_id='{ClientId}', redirect_uri='{RedirectUri}', " +
         "scope='{Scope}', response_type='{ResponseType}'",
         request.ClientId, request.RedirectUri, request.Scope, request.ResponseType);

      // Build return URL for post-login continuation
      var returnUrl = Request.PathBase + Request.Path + Request.QueryString;

      // Explicitly authenticate using the Identity application cookie
      var authResult = await HttpContext.AuthenticateAsync(
         IdentityConstants.ApplicationScheme);

      if (!authResult.Succeeded) {
         logger.LogInformation(
            "Authorize: no Identity cookie -> challenge, returnUrl='{ReturnUrl}'",
            returnUrl);

         return Challenge(new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme);
      }

      // Load domain user
      var user = await users.GetUserAsync(authResult.Principal!);
      if (user is null) {
         logger.LogWarning(
            "Authorize: Identity cookie principal has no user -> challenge, returnUrl='{ReturnUrl}'",
            returnUrl
         );

         return Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme
         );
      }

      // Create principal from ASP.NET Identity
      var principal = await signIn.CreateUserPrincipalAsync(user);
      var identity = (ClaimsIdentity)principal.Identity!;

      //--- Mandatory OIDC subject (sub) --------------------------------------
      var subject =
         principal.FindFirstValue(ClaimTypes.NameIdentifier)
         ?? user.Id;

      principal.SetClaim(AuthClaims.Subject, subject);

      //--- Profile / standard claims ------------------------------------------
      if (!string.IsNullOrWhiteSpace(user.Email))
         identity.AddClaim(new Claim(AuthClaims.Email, user.Email));

      if (!string.IsNullOrWhiteSpace(user.UserName))
         identity.AddClaim(new Claim(AuthClaims.PreferredUsername, user.UserName));

      //--- Domain-specific claims ---------------------------------------------
      identity.AddClaim(new Claim(AuthClaims.AccountType, user.AccountType));

      // Admin rights (bitmask enum → int → string)
      identity.AddClaim(new Claim(AuthClaims.AdminRights,
         ((int)user.AdminRights).ToString()));

      // Lifecycle timestamps (ISO-8601, stable for all clients)
      identity.AddClaim(new Claim(AuthClaims.CreatedAt,
         user.CreatedAt.ToUniversalTime().ToString("O")));

      identity.AddClaim(new Claim(AuthClaims.UpdatedAt,
         user.UpdatedAt.ToUniversalTime().ToString("O")));

      //--- Scopes & resources -------------------------------------------------
      var scopes = request.GetScopes().ToArray();
      principal.SetScopes(scopes);
      principal.SetResources(_auth.ScopeApi);

      logger.LogInformation(
         "Authorize: user='{UserName}', sub='{Sub}', scopes=[{Scopes}]",
         user.UserName, subject, string.Join(", ", scopes));

      //--- Destinations mapping -----------------------------------------------
      foreach (var claim in principal.Claims)
         claim.SetDestinations(
            ClaimDestinations.GetDestinations(claim, principal));

      return SignIn(principal,
         OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
   }

   // --------------------------------------------------------------------
   // /connect/token
   // --------------------------------------------------------------------
   [HttpPost("/" + AuthServerOptions.TokenEndpointPath)]
   public async Task<IActionResult> Token(CancellationToken ct) {
      var request = HttpContext.GetOpenIddictServerRequest()
         ?? throw new InvalidOperationException("OpenID Connect request missing.");

      logger.LogInformation(
         "Token request: grant_type='{GrantType}', client_id='{ClientId}', scope='{Scope}'",
         request.GrantType, request.ClientId, request.Scope);

      //--- Authorization Code / Refresh Token flow ----------------------------
      if (request.IsAuthorizationCodeGrantType() ||
          request.IsRefreshTokenGrantType()) {
         var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

         logger.LogInformation(
            "Token: code/refresh -> issuing tokens for client_id='{ClientId}'",
            request.ClientId);

         return SignIn(
            result.Principal!,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
      }

      //--- Client Credentials flow --------------------------------------------
      if (request.IsClientCredentialsGrantType()) {
         logger.LogInformation(
            "Token: client_credentials -> issuing access token for client_id='{ClientId}'",
            request.ClientId);

         var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

         identity.AddClaim(new Claim(AuthClaims.Subject, request.ClientId!));
         identity.AddClaim(new Claim(AuthClaims.AccountType, "service"));

         var principal = new ClaimsPrincipal(identity);

         principal.SetScopes(request.GetScopes());
         principal.SetResources(_auth.ScopeApi);

         foreach (var claim in principal.Claims)
            claim.SetDestinations(Destinations.AccessToken);

         return SignIn(
            principal,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
      }

      logger.LogWarning(
         "Token: unsupported grant_type '{GrantType}'",
         request.GrantType);

      return BadRequest(new { error = "unsupported_grant_type" });
   }

   // --------------------------------------------------------------------
   // /connect/userinfo
   // --------------------------------------------------------------------
   [Authorize(AuthenticationSchemes =
      OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
   [HttpGet("/" + AuthServerOptions.UserInfoEndpointPath)]
   public IActionResult UserInfo() {
      logger.LogInformation(
         "UserInfo request: sub='{Sub}', azp='{Azp}'",
         User.FindFirst(AuthClaims.Subject)?.Value,
         User.FindFirst("azp")?.Value
      );

      return Ok(new {
         sub = User.FindFirst(AuthClaims.Subject)?.Value,
         preferred_username = User.FindFirst(AuthClaims.PreferredUsername)?.Value,
         email = User.FindFirst(AuthClaims.Email)?.Value,
         account_type = User.FindFirst(AuthClaims.AccountType)?.Value,
         admin_rights = User.FindFirst(AuthClaims.AdminRights)?.Value,
         created_at = User.FindFirst(AuthClaims.CreatedAt)?.Value,
         updated_at = User.FindFirst(AuthClaims.UpdatedAt)?.Value
      });
   }

   /*
   ======================================================================
   DIDAKTIK / LERNZIELE
   ======================================================================

   Ziel dieses Controllers ist es, den vollständigen OAuth2 / OpenID
   Connect Authorization Code Flow mit OpenIddict zu verstehen und
   selbst kontrolliert umzusetzen – ohne Blackbox.

   Lernziele:

   1. Trennung von Verantwortung
      - ASP.NET Identity ist ausschließlich für Login & Benutzerverwaltung
      - OpenIddict ist ausschließlich für Token-Erzeugung und Protokoll
      - Domain-spezifische Informationen (Customer, Employee, Rights)
        werden explizit als Claims modelliert

   2. Bewusste Claim-Modellierung
      - Standard-OIDC-Claims (sub, email, profile)
      - Erweiterung um fachliche Claims (account_type, admin_rights)
      - Keine impliziten Rollenannahmen

   3. Scopes steuern Sichtbarkeit
      - profile → persönliche Daten im ID Token
      - api     → fachliche Claims im Access Token
      - Prinzip der minimalen Offenlegung

   4. Destinations sind entscheidend
      - Jeder Claim muss explizit einem Token zugewiesen werden
      - ID Token ≠ Access Token
      - Sicherheit entsteht durch bewusste Entscheidung

   5. Ein Server – mehrere Client-Typen
      - Browser (MVC / Blazor)
      - Mobile (Android, PKCE)
      - Services (Client Credentials)
      - Alle nutzen denselben Identity-Kern

   Ergebnis:
   Studierende verstehen, warum moderne Auth-Systeme
   nicht "einfach konfiguriert", sondern bewusst modelliert werden.

   ======================================================================
   #1#
}*/