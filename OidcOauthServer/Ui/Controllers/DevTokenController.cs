// using System.Security.Claims;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Identity;
// using Microsoft.AspNetCore.Mvc;
// using OidcOauthServer.Data;
// using OpenIddict.Abstractions;
// using OpenIddict.Server.AspNetCore;
// using static OpenIddict.Abstractions.OpenIddictConstants;
//
// namespace OidcOauthServer.Ui.Controllers;
//
// /// <summary>
// /// DEV-only endpoint to obtain an access token with email+password (Postman-friendly).
// ///
// /// IMPORTANT:
// /// - Not for production.
// /// - Use only in Development environment.
// /// - Generates a real OpenIddict access token (same issuer/signing keys).
// /// </summary>
// [ApiController]
// [Route("dev")]
// public sealed class DevTokenController(
//    IWebHostEnvironment env,
//    UserManager<ApplicationUser> users,
//    SignInManager<ApplicationUser> signIn
// ) : Controller
// {
//    [AllowAnonymous]
//    [HttpPost("token")]
//    public async Task<IActionResult> Token([FromBody] DevLoginDto dto, CancellationToken ct)
//    {
//       if (!env.IsDevelopment())
//          return NotFound(); // hide endpoint outside dev
//
//       if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
//          return BadRequest(new { error = "email_and_password_required" });
//
//       var user = await users.FindByEmailAsync(dto.Email);
//       if (user is null)
//          return Unauthorized();
//
//       // Validate password using ASP.NET Identity
//       var valid = await users.CheckPasswordAsync(user, dto.Password);
//       if (!valid)
//          return Unauthorized();
//
//       // Build the principal (same minimal claims logic as /connect/authorize)
//       var principal = await signIn.CreateUserPrincipalAsync(user);
//       var identity = (ClaimsIdentity)principal.Identity!;
//
//       identity.AddClaim(new Claim("account_type", user.AccountType));
//
//       if (user.CustomerId is not null)
//          identity.AddClaim(new Claim("customer_id", user.CustomerId.Value.ToString()));
//
//       if (user.EmployeeId is not null)
//          identity.AddClaim(new Claim("employee_id", user.EmployeeId.Value.ToString()));
//
//       if (user.AdminRights is not null)
//          identity.AddClaim(new Claim("admin_rights", user.AdminRights.Value.ToString()));
//
//       // Force API scope/resource
//       principal.SetScopes(AuthServerDefaults.ScopeApi);
//       principal.SetResources(AuthServerDefaults.ScopeApi);
//
//       // Access token only (no id_token here)
//       foreach (var claim in principal.Claims)
//       {
//          claim.SetDestinations(claim.Type switch
//          {
//             Claims.Subject => new[] { Destinations.AccessToken },
//             "account_type" or "customer_id" or "employee_id" or "admin_rights"
//                => new[] { Destinations.AccessToken },
//             _ => Array.Empty<string>()
//          });
//       }
//
//       return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
//    }
// }
//
// public sealed record DevLoginDto(string Email, string Password);
//
// /*
// DE:
// - /dev/token ist ein Entwickler-Endpunkt für Postman.
// - Du sendest Email+Passwort und bekommst ein echtes Access Token zurück.
// - Dieser Endpunkt ist absichtlich DEV-only und wird in Production versteckt (NotFound).
// */
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OidcOauthServer.Data;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcOauthServer.Ui.Controllers;

[ApiController]
[Route("dev")]
public sealed class DevTokenController(
   IWebHostEnvironment env,
   UserManager<ApplicationUser> users,
   SignInManager<ApplicationUser> signIn,
   IOptions<AuthServerOptions> authOptions
) : Controller
{
   [AllowAnonymous]
   [HttpPost("token")]
   public async Task<IActionResult> Token([FromBody] DevLoginDto dto, CancellationToken ct)
   {
      if (!env.IsDevelopment())
         return NotFound();

      if (string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
         return BadRequest(new { error = "email_and_password_required" });

      var user = await users.FindByEmailAsync(dto.Email);
      if (user is null)
         return Unauthorized();

      var valid = await users.CheckPasswordAsync(user, dto.Password);
      if (!valid)
         return Unauthorized();

      var principal = await signIn.CreateUserPrincipalAsync(user);
      var identity = (ClaimsIdentity)principal.Identity!;

      identity.AddClaim(new Claim("account_type", user.AccountType));

      if (user.CustomerId is not null)
         identity.AddClaim(new Claim("customer_id", user.CustomerId.Value.ToString()));

      if (user.EmployeeId is not null)
         identity.AddClaim(new Claim("employee_id", user.EmployeeId.Value.ToString()));

      if (user.AdminRights is not null)
         identity.AddClaim(new Claim("admin_rights", user.AdminRights.Value.ToString()));

      var apiScope = authOptions.Value.ScopeApi;

      // scope/resource
      principal.SetScopes(apiScope);
      principal.SetResources(apiScope);

      foreach (var claim in principal.Claims)
      {
         claim.SetDestinations(claim.Type switch
         {
            Claims.Subject => new[] { Destinations.AccessToken },
            "account_type" or "customer_id" or "employee_id" or "admin_rights"
               => new[] { Destinations.AccessToken },
            _ => Array.Empty<string>()
         });
      }

      return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
   }
}

public sealed record DevLoginDto(string Email, string Password);
