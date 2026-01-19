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
) : Controller
{
   /// <summary>
   /// Development-only token endpoint.
   ///
   /// Allows issuing an access token by posting email + password.
   /// This endpoint must NEVER exist in production environments.
   /// </summary>
   [AllowAnonymous]
   [HttpPost("token")]
   public async Task<IActionResult> Token(
      [FromBody] DevLoginDto dto,
      CancellationToken ct
   )
   {
      if (!env.IsDevelopment())
         return NotFound();

      if (string.IsNullOrWhiteSpace(dto.Email) ||
          string.IsNullOrWhiteSpace(dto.Password))
      {
         return BadRequest(new { error = "email_and_password_required" });
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

      principal.SetClaim(AuthClaims.Subject, subject);

      // Domain claims
      identity.AddClaim(new Claim(AuthClaims.AccountType, user.AccountType));

      // if (user.CustomerId is not null)
      //    identity.AddClaim(new Claim("customer_id", user.CustomerId.Value.ToString()));
      //
      // if (user.EmployeeId is not null)
      //    identity.AddClaim(new Claim("employee_id", user.EmployeeId.Value.ToString()));
      //
      // if (user.AdminRights is not null)
      //    identity.AddClaim(new Claim(AuthClaims.AdminRights, user.AdminRights.Value.ToString()));

      // Scope / resource
      var apiScope = authOptions.Value.ScopeApi;
      principal.SetScopes(apiScope);
      principal.SetResources(apiScope);

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

public sealed record DevLoginDto(string Email, string Password);

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

2) Warum trotzdem SignInManager + ClaimsPrincipal?
--------------------------------------------------
Auch im Dev-Modus:
- wird das echte Identity-System genutzt
- entstehen realistische Claims
- bleiben Tokens kompatibel mit dem echten OIDC-Flow

Kein Mocking, kein Sonderformat.

3) Warum zentrale ClaimDestinations?
-----------------------------------
OpenIddict verlangt explizit:
- welche Claims im Access Token landen
- welche im ID Token landen

Durch die zentrale Klasse:
- kein Copy & Paste
- identisches Verhalten in
  - /connect/authorize
  - /connect/token
  - /dev/token

4) Architektur-Prinzip
----------------------
- Identity = Authentifizierung
- OpenIddict = Token-Ausgabe
- Claims = Domänenwissen
- Policies (später) = Autorisierung

5) Wichtige Regel
-----------------
Dieser Controller darf:
- niemals in Production aktiv sein
- niemals echte Clients ersetzen
- nur Entwicklung beschleunigen

==========================================================
*/
