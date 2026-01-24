using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OidcOauthServer.Auth.Claims;
using OidcOauthServer.Auth.Options;
using OidcOauthServer.Infrastructure.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace OidcOauthServer.Auth.Controllers;

[ApiController]
[Route("dev")]
public sealed class DevTokenController(
   IWebHostEnvironment env,
   UserManager<ApplicationUser> users,
   SignInManager<ApplicationUser> signIn,
   IOptions<AuthServerOptions> authOptions
) : Controller {

   /// <summary>
   /// Development-only token endpoint.
   ///
   /// Allows issuing an access token by posting email + password (+ optional ApiKey).
   /// This endpoint must NEVER exist in production environments.
   /// </summary>
   [AllowAnonymous]
   [HttpPost("token")]
   public async Task<IActionResult> Token(
      [FromBody] DevLoginDto dto,
      CancellationToken ct
   ) {
      if (!env.IsDevelopment())
         return NotFound();

      if (string.IsNullOrWhiteSpace(dto.Email) ||
          string.IsNullOrWhiteSpace(dto.Password)) {
         return BadRequest(new { error = "email_and_password_required" });
      }

      // Resolve API scope/resource from configuration
      var apiKey = string.IsNullOrWhiteSpace(dto.Api) ? "CarRentalApi" : dto.Api.Trim();

      if (!authOptions.Value.Apis.TryGetValue(apiKey, out var api)) {
         return BadRequest(new {
            error = "unknown_api",
            api = apiKey,
            allowed = authOptions.Value.Apis.Keys.OrderBy(x => x).ToArray()
         });
      }

      // Authenticate user via ASP.NET Identity
      var user = await users.FindByEmailAsync(dto.Email);
      if (user is null)
         return Unauthorized();

      var valid = await users.CheckPasswordAsync(user, dto.Password);
      if (!valid)
         return Unauthorized();

      // Create ClaimsPrincipal using Identity infrastructure
      var principal = await signIn.CreateUserPrincipalAsync(user);
      var identity = (ClaimsIdentity)principal.Identity!;

      // Mandatory OIDC subject (sub)
      var subject =
         principal.FindFirstValue(ClaimTypes.NameIdentifier)
         ?? user.Id;

      // Use "sub" claim name consistent with your APIs (IdentityClaims.Subject = "sub")
      principal.SetClaim(AuthClaims.Subject, subject);

      // Domain claims (keep minimal: sub, email, created_at, admin_rights)
      identity.AddClaim(new Claim(AuthClaims.AccountType, user.AccountType));

      // Scope + Resource (IMPORTANT: scope != resource)
      principal.SetScopes(api.Scope);         // e.g. "carrental_api"
      principal.SetResources(api.Resource);   // e.g. "carrental-api"

      // Apply centralized destinations mapping
      foreach (var claim in principal.Claims)
         claim.SetDestinations(
            ClaimDestinations.GetDestinations(claim, principal)
         );

      return SignIn(
         principal,
         OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
      );
   }
}

/// <summary>
/// Dev login request.
/// Api is optional and selects which API the access token is meant for.
/// Example:
///  - "CarRentalApi" -> scope=carrental_api, resource=carrental-api
/// </summary>
public sealed record DevLoginDto(
   string Email,
   string Password,
   string? Api = "CarRentalApi"
);

/*
==========================================================
DIDAKTIK / LERNZIELE (DE)
==========================================================

1) Warum gibt es diesen Controller?
----------------------------------
Dieser Controller dient ausschließlich der Entwicklung und dem Testen.
Er erlaubt das Ausstellen von Access Tokens ohne:
- Browser Redirects
- OIDC Authorization Code Flow
- Login UI

Das beschleunigt:
- API-Tests
- Mobile-Client-Entwicklung
- Postman / curl / Integrationstests

2) Was ist der zentrale Lernpunkt hier?
---------------------------------------
"scope" und "resource/audience" sind NICHT dasselbe:

- Scope  (z. B. "carrental_api")  = Berechtigung / Capability (was darf der Client?)
- Resource (z. B. "carrental-api") = Ziel-API / Audience (für wen ist das Token gedacht?)

Im Resource Server (z. B. CarRentalApi) wird typischerweise die Audience geprüft.

3) Warum ApiKey im DTO?
-----------------------
Damit man beim Testen gezielt Tokens für verschiedene APIs ausstellen kann:
- CarRentalApi, BankingApi, ImagesApi

So bleibt das Setup skalierbar, ohne Codeänderungen in diesem Controller.
Die Wahrheit steht in appsettings.json:
AuthServer:Apis:{Key}:{Scope,Resource}

4) Warum SignInManager + ClaimsPrincipal?
-----------------------------------------
Auch im Dev-Modus:
- wird das echte Identity-System genutzt
- entstehen realistische Claims
- bleiben Tokens kompatibel mit dem echten OIDC-Flow

Kein Mocking, kein Sonderformat.

5) Warum zentrale ClaimDestinations?
------------------------------------
OpenIddict verlangt explizit:
- welche Claims im Access Token landen
- welche im ID Token landen

Durch die zentrale Klasse:
- kein Copy & Paste
- identisches Verhalten in
  - /connect/authorize
  - /connect/token
  - /dev/token

6) Wichtige Regel
-----------------
Dieser Controller darf:
- niemals in Production aktiv sein
- niemals echte Clients ersetzen
- nur Entwicklung beschleunigen
==========================================================
*/
