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

      // Authenticate using Identity cookie (interactive login)
      var authResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

      if (!authResult.Succeeded) {
         logger.LogInformation("Authorize: no Identity cookie -> challenge, returnUrl='{ReturnUrl}'", returnUrl);

         return Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme
         );
      }

      // Load user from Identity
      var user = await users.GetUserAsync(authResult.Principal!);
      if (user is null) {
         logger.LogWarning("Authorize: Identity cookie principal has no user -> challenge, returnUrl='{ReturnUrl}'", returnUrl);

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
      identity.AddClaim(new Claim(AuthClaims.AdminRights, ((int)user.AdminRights).ToString()));

      // Lifecycle timestamps (ISO-8601)
      identity.AddClaim(new Claim(AuthClaims.CreatedAt, user.CreatedAt.ToUniversalTime().ToString("O")));
      identity.AddClaim(new Claim(AuthClaims.UpdatedAt, user.UpdatedAt.ToUniversalTime().ToString("O")));

      // --- Scopes & resources ------------------------------------------------
      // Scopes come from the client request (OpenIddict already restricts them via client permissions).
      var requestedScopes = request.GetScopes().ToArray();
      principal.SetScopes(requestedScopes);

      // Resources/audiences are derived from API scopes (Scope -> Resource mapping).
      // We set them explicitly so it's transparent & debuggable.
      var resources = ResolveResourcesFromScopes(requestedScopes);

      // Only set resources if at least one API resource was derived.
      // For pure "openid profile" requests, we leave resources empty.
      if (resources.Length > 0)
         principal.SetResources(resources);

      logger.LogInformation(
         "Authorize: user='{UserName}', sub='{Sub}', scopes=[{Scopes}], resources=[{Resources}]",
         user.UserName,
         subject,
         string.Join(", ", requestedScopes),
         resources.Length == 0 ? "<none>" : string.Join(", ", resources)
      );

      // --- Destinations mapping ---------------------------------------------
      foreach (var claim in principal.Claims)
         claim.SetDestinations(ClaimDestinations.GetDestinations(claim, principal));

      return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

      // --- Authorization Code / Refresh Token -------------------------------
      if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()) {

         var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );

         logger.LogInformation("Token: code/refresh -> issuing tokens for client_id='{ClientId}'", request.ClientId);

         return SignIn(result.Principal!, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
      }

      // --- Client Credentials ------------------------------------------------
      if (request.IsClientCredentialsGrantType()) {

         logger.LogInformation("Token: client_credentials -> issuing access token for client_id='{ClientId}'", request.ClientId);

         var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

         identity.AddClaim(new Claim(AuthClaims.Subject, request.ClientId!));
         identity.AddClaim(new Claim(AuthClaims.AccountType, "service"));

         var principal = new ClaimsPrincipal(identity);

         var requestedScopes = request.GetScopes().ToArray();
         principal.SetScopes(requestedScopes);

         var resources = ResolveResourcesFromScopes(requestedScopes);
         if (resources.Length > 0)
            principal.SetResources(resources);

         foreach (var claim in principal.Claims)
            claim.SetDestinations(Destinations.AccessToken);

         logger.LogInformation(
            "Token: client_credentials -> client_id='{ClientId}', scopes=[{Scopes}], resources=[{Resources}]",
            request.ClientId,
            string.Join(", ", requestedScopes),
            resources.Length == 0 ? "<none>" : string.Join(", ", resources)
         );

         return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

      // Non-API scopes we ignore for resources
      static bool IsNonApiScope(string s)
         => s.Equals("openid", StringComparison.Ordinal) ||
            s.Equals("profile", StringComparison.Ordinal);

      // Map requested API scopes -> resources/audiences using configuration.
      // Example:
      //  requestedScopes contains "carrental_api" -> returns "carrental-api"
      var apiScopesRequested = requestedScopes
         .Where(s => !IsNonApiScope(s))
         .Distinct(StringComparer.Ordinal)
         .ToArray();

      if (apiScopesRequested.Length == 0)
         return Array.Empty<string>();

      // known scopes from config
      var known = _auth.Apis.Values.ToDictionary(a => a.Scope, a => a.Resource, StringComparer.Ordinal);

      var resources = new List<string>(capacity: apiScopesRequested.Length);

      foreach (var scope in apiScopesRequested) {
         if (known.TryGetValue(scope, out var resource)) {
            resources.Add(resource);
         }
         else {
            // This should not happen if:
            // - client permissions are correct
            // - scopes are seeded
            // But if it does, we log and ignore to avoid producing wrong aud.
            logger.LogWarning(
               "Unknown API scope requested: '{Scope}'. No resource/audience mapping found in AuthServer:Apis.",
               scope
            );
         }
      }

      return resources
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
      - Nur API-Scopes führen zu Resources / aud (openid/profile nicht)

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