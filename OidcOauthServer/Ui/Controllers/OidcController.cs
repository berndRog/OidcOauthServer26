using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OidcOauthServer.Data;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcOauthServer.Ui.Controllers;

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
      HttpContext.Response.Headers["X-OIDC-Authorize"] = "hit";

      var request = HttpContext.GetOpenIddictServerRequest()
         ?? throw new InvalidOperationException("OIDC request missing.");

      var returnUrl = Request.PathBase + Request.Path + Request.QueryString;

      // ✅ WICHTIG: explizit das Identity-Cookie prüfen (nicht default)
      var authResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

      if (!authResult.Succeeded)
      {
         // ✅ sauber: Challenge mit RedirectUri
         return Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme
         );
      }

      var user = await users.GetUserAsync(authResult.Principal!);
      if (user is null)
      {
         return Challenge(
            new AuthenticationProperties { RedirectUri = returnUrl },
            IdentityConstants.ApplicationScheme
         );
      }

      var principal = await signIn.CreateUserPrincipalAsync(user);
      var identity = (ClaimsIdentity)principal.Identity!;

      // ✅ Mandatory: subject (sub)
      // Robust: wenn Identity dir schon NameIdentifier gibt, verwende den, sonst user.Id
      var sub =
         principal.FindFirstValue(ClaimTypes.NameIdentifier)
         ?? principal.FindFirstValue(Claims.Subject)
         ?? user.Id;

      principal.SetClaim(Claims.Subject, sub);

      // -----------------------------------------------------------------
      // Domain claims
      // -----------------------------------------------------------------
      identity.AddClaim(new Claim("account_type", user.AccountType));

      if (user.CustomerId is not null)
         identity.AddClaim(new Claim("customer_id", user.CustomerId.Value.ToString()));

      if (user.EmployeeId is not null)
         identity.AddClaim(new Claim("employee_id", user.EmployeeId.Value.ToString()));

      if (user.AdminRights is not null)
         identity.AddClaim(new Claim("admin_rights", user.AdminRights.Value.ToString()));

      // Requested scopes (openid, profile, api, ...)
      principal.SetScopes(request.GetScopes());

      // API audience/resource
      principal.SetResources(_auth.ScopeApi);

      foreach (var claim in principal.Claims)
         claim.SetDestinations(GetDestinations(claim, principal));

      return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
   }

   // --------------------------------------------------------------------
   // /connect/token
   // --------------------------------------------------------------------
   [HttpPost("/" + AuthServerOptions.TokenEndpointPath)]
   public async Task<IActionResult> Token(CancellationToken ct)
   {
      var request = HttpContext.GetOpenIddictServerRequest()
         ?? throw new InvalidOperationException("OIDC request missing.");

      // Authorization Code / Refresh Token
      if (request.IsAuthorizationCodeGrantType() ||
          request.IsRefreshTokenGrantType())
      {
         var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
         );

         var principal = result.Principal
            ?? throw new InvalidOperationException("Missing principal.");

         return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
      }

      // Client Credentials
      if (request.IsClientCredentialsGrantType())
      {
         var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

         identity.AddClaim(new Claim(Claims.Subject, request.ClientId ?? _auth.ServiceClient.ClientId));
         identity.AddClaim(new Claim("account_type", "service"));

         var principal = new ClaimsPrincipal(identity);

         principal.SetScopes(request.GetScopes());
         principal.SetResources(_auth.ScopeApi);

         foreach (var claim in principal.Claims)
            claim.SetDestinations(Destinations.AccessToken);

         return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
      }

      return BadRequest(new { error = "unsupported_grant_type" });
   }

   // --------------------------------------------------------------------
   // /connect/userinfo
   // --------------------------------------------------------------------
   [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
   [HttpGet("/" + AuthServerOptions.UserInfoEndpointPath)]
   public IActionResult UserInfo() => Ok(new
   {
      sub = User.FindFirst(Claims.Subject)?.Value,
      account_type = User.FindFirst("account_type")?.Value,
      customer_id = User.FindFirst("customer_id")?.Value,
      employee_id = User.FindFirst("employee_id")?.Value,
      admin_rights = User.FindFirst("admin_rights")?.Value
   });

   private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
   {
      if (claim.Type == Claims.Subject)
         return new[] { Destinations.AccessToken, Destinations.IdentityToken };

      if (claim.Type == Claims.Name)
         return principal.HasScope(Scopes.Profile)
            ? new[] { Destinations.IdentityToken }
            : Array.Empty<string>();

      if (claim.Type is "account_type" or "customer_id" or "employee_id" or "admin_rights")
         return new[] { Destinations.AccessToken };

      return Array.Empty<string>();
   }
}
