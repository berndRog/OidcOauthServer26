using IdentityAccessServer.Infrastructure.Identity;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace IdentityAccessServer.Auth.Controllers;

[ApiController]
[Route("connect")]
public sealed class EndSessionController(
   IOpenIddictApplicationManager applicationManager,
   SignInManager<ApplicationUser> signInManager,
   ILogger<EndSessionController> logger
) : Controller {

   // GET /connect/endsession
   [HttpGet("endsession")]
   public async Task<IActionResult> EndSession(CancellationToken ct) {

      // OpenIddict 7.x: read request parameters from the OpenIddict server request.
      var request = HttpContext.GetOpenIddictServerRequest();
      if (request is null) {
         logger.LogError("Missing OpenIddict server request.");
         return BadRequest("Invalid OIDC logout request.");
      }

      var clientId = request.ClientId;
      var postLogoutRedirectUri = request.PostLogoutRedirectUri;

      logger.LogInformation(
         "End-session request. client_id='{ClientId}', post_logout_redirect_uri='{Uri}'",
         clientId ?? "(none)",
         postLogoutRedirectUri ?? "(none)"
      );

      // 1) Choose a safe default to prevent open redirects.
      const string safeFallback = "/";
      var redirect = safeFallback;

      // 2) Validate the post_logout_redirect_uri against the registered client.
      if (Uri.TryCreate(postLogoutRedirectUri, UriKind.Absolute, out var requestedUri)) {
         var isAllowed = await IsPostLogoutRedirectAllowedAsync(requestedUri, clientId, ct);
         if (isAllowed) {
            redirect = requestedUri.ToString();
            logger.LogInformation("Logout redirect approved: {Redirect}", redirect);
         } else {
            logger.LogWarning("Logout redirect rejected: {Uri}", requestedUri);
         }
      } else if (!string.IsNullOrWhiteSpace(postLogoutRedirectUri)) {
         logger.LogWarning("Invalid post_logout_redirect_uri: {Uri}", postLogoutRedirectUri);
      }

      // 3) Terminate the local Identity session on the authorization server.
      await signInManager.SignOutAsync();

      // 4) Let OpenIddict complete the end-session flow and perform the redirect.
      // This is important: returning Redirect(...) bypasses OpenIddict's protocol handling.
      var props = new AuthenticationProperties {
         RedirectUri = redirect
      };

      return SignOut(props, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
   }

   private async Task<bool> IsPostLogoutRedirectAllowedAsync(
      Uri requested,
      string? clientId,
      CancellationToken ct
   ) {
      if (!string.IsNullOrWhiteSpace(clientId)) {
         var app = await applicationManager.FindByClientIdAsync(clientId, ct);
         if (app is null) return false;

         var uris = await applicationManager.GetPostLogoutRedirectUrisAsync(app, ct);
         return uris.Select(TryParseAbsoluteUri).Any(u => u is not null && UriEquals(u, requested));
      }

      await foreach (var app in applicationManager.ListAsync(count: 100, offset: 0, ct)) {
         var uris = await applicationManager.GetPostLogoutRedirectUrisAsync(app, ct);
         if (uris.Select(TryParseAbsoluteUri).Any(u => u is not null && UriEquals(u, requested)))
            return true;
      }

      return false;
   }

   private static Uri? TryParseAbsoluteUri(string value)
      => Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : null;

   private static bool UriEquals(Uri a, Uri b) {
      var leftA = a.GetLeftPart(UriPartial.Path).TrimEnd('/');
      var leftB = b.GetLeftPart(UriPartial.Path).TrimEnd('/');
      return string.Equals(leftA, leftB, StringComparison.OrdinalIgnoreCase);
   }
}

/*
===============================================================================
DIDAKTIK & LERNZIELE (DE)
===============================================================================

1) Warum nicht einfach Redirect(...)?
-------------------------------------
Wenn Passthrough aktiv ist, liefert deine App die HTTP-Antwort.
Aber: Der End-Session-Flow ist ein OIDC-Protokollflow.
Wenn du direkt Redirect(...) zurückgibst, umgehst du OpenIddicts
eigene Protokoll-Finalisierung.

Best Practice:
Nach SignOut der lokalen Identity-Session immer
   return SignOut(props, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

2) Rolle von post_logout_redirect_uri
-------------------------------------
Das ist eine sicherheitskritische URL.
Sie muss:
- absolut sein
- und beim Client als PostLogoutRedirectUri registriert sein (Whitelist)

Merksatz:
Der AuthServer validiert Redirects, nicht der Client.

3) Was löst das praktisch?
--------------------------
Der RP (Blazor SSR/WASM OIDC-Handler) kann den Logout sauber abschließen,
statt am technischen Callback (z.B. /signout-callback-oidc) zu "hängen".

===============================================================================
*/
