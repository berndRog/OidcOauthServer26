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

[ApiController]
public sealed class OidcController(
   UserManager<ApplicationUser> users,
   SignInManager<ApplicationUser> signIn,
   IOptions<AuthServerOptions> authOptions
) : Controller
{
   private readonly AuthServerOptions _auth = authOptions.Value;

   // --------------------------------------------------------------------
   // /connect/authorize
   // --------------------------------------------------------------------
   [HttpGet("/" + AuthServerOptions.AuthorizationEndpointPath)]
   public async Task<IActionResult> Authorize(CancellationToken ct)
   {
      var request = HttpContext.GetOpenIddictServerRequest()
         ?? throw new InvalidOperationException("OpenID Connect request missing.");

      // Build return URL for post-login continuation
      var returnUrl = Request.PathBase + Request.Path + Request.QueryString;

      // Explicitly authenticate using the Identity application cookie
      var authResult = await HttpContext.AuthenticateAsync(
         IdentityConstants.ApplicationScheme
      );

      if (!authResult.Succeeded)
      {
         return Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme
         );
      }

      // Load domain user
      var user = await users.GetUserAsync(authResult.Principal!);
      if (user is null)
      {
         return Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme
         );
      }

      // Create principal from ASP.NET Identity
      var principal = await signIn.CreateUserPrincipalAsync(user);
      var identity = (ClaimsIdentity)principal.Identity!;
      
      // -----------------------------------------------------------------
      // Mandatory OIDC subject (sub)
      // -----------------------------------------------------------------
      var subject =
         principal.FindFirstValue(ClaimTypes.NameIdentifier)
         ?? user.Id;

      principal.SetClaim(AuthClaims.Subject, subject);

      // -----------------------------------------------------------------
      // Profile / standard claims
      // -----------------------------------------------------------------
      if (!string.IsNullOrWhiteSpace(user.Email))
         identity.AddClaim(new Claim(AuthClaims.Email, user.Email));

      if (!string.IsNullOrWhiteSpace(user.UserName))
         identity.AddClaim(new Claim(AuthClaims.PreferredUsername, user.UserName));

      // -----------------------------------------------------------------
      // Domain-specific claims
      // -----------------------------------------------------------------
      identity.AddClaim(new Claim(
         AuthClaims.AccountType,
         user.AccountType
      ));

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

      
      // -----------------------------------------------------------------
      // Scopes & resources
      // -----------------------------------------------------------------
      principal.SetScopes(request.GetScopes());
      principal.SetResources(_auth.ScopeApi);

      // -----------------------------------------------------------------
      // Destinations mapping
      // -----------------------------------------------------------------
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
   public async Task<IActionResult> Token(CancellationToken ct)
   {
      var request = HttpContext.GetOpenIddictServerRequest()
         ?? throw new InvalidOperationException("OpenID Connect request missing.");

      // Authorization Code / Refresh Token flow
      if (request.IsAuthorizationCodeGrantType() ||
          request.IsRefreshTokenGrantType()
      ) {
         var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );

         return SignIn(
            result.Principal!,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );
      }

      // Client Credentials flow
      if (request.IsClientCredentialsGrantType()) {
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
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );
      }

      return BadRequest(new { error = "unsupported_grant_type" });
   }

   // --------------------------------------------------------------------
   // /connect/userinfo
   // --------------------------------------------------------------------
   [Authorize(
      AuthenticationSchemes =
         OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme
   )]
   [HttpGet("/" + AuthServerOptions.UserInfoEndpointPath)]
   public IActionResult UserInfo() => Ok(new
   {
      sub = User.FindFirst(AuthClaims.Subject)?.Value,
      email = User.FindFirst(AuthClaims.Email)?.Value,
      preferred_username = User.FindFirst(AuthClaims.PreferredUsername)?.Value,
      account_type = User.FindFirst(AuthClaims.AccountType)?.Value,
      customer_id = User.FindFirst("customer_id")?.Value,
      employee_id = User.FindFirst("employee_id")?.Value,
      admin_rights = User.FindFirst(AuthClaims.AdminRights)?.Value
   });

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
   */
}
