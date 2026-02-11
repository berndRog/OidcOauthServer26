using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace BankingBlazorSSR.Controllers;

/// <summary>
/// Handles the authentication flow for the Blazor SSR client.
/// Provides endpoints that delegate to the OIDC middleware.
/// - identity/login → initiates OIDC login (Challenge)
/// - identity/logout → initiates OIDC logout (SignOut)
/// - identity/signed-out → technical callback after OIDC logout
///   redirects to final UX page ("/") after logout completes.
/// </summary>
[Route("identity")]
public class IdentityController(
   ILogger<IdentityController> logger
) : Controller {
   /// <summary>
   /// Initiates the OIDC login flow.
   ///
   /// - If the user is already authenticated, redirect to the (safe) returnUrl.
   /// - Otherwise, challenge the OIDC middleware (redirects to the authorization server).
   /// </summary>
   /// <param name="returnUrl">Optional local URL to redirect to after successful login.</param>
   [HttpGet("login")]
   public IActionResult Login(string? returnUrl = null) {
      logger.LogInformation("Login requested. ReturnUrl: {ReturnUrl}", returnUrl ?? "(none)");

      // If the user is already authenticated, we can redirect immediately.
      if (User.Identity?.IsAuthenticated == true) {
         logger.LogInformation("User already authenticated: {User}", User.Identity.Name);

         // Prevent open redirect vulnerabilities: only allow local return URLs.
         var targetUrl = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
         if (Url.IsLocalUrl(targetUrl))
            return LocalRedirect(targetUrl);

         return LocalRedirect("/");
      }

      // AuthenticationProperties.RedirectUri is where the client app continues AFTER the OIDC login succeeds.
      // This must be a local URL in the client application.
      var target = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;

      // Ensure we don't accept external URLs (defense in depth).
      if (!Url.IsLocalUrl(target))
         target = "/";

      var props = new AuthenticationProperties {
         RedirectUri = target,
         IsPersistent = false // session cookie (not persistent)
      };

      logger.LogInformation(
         "Challenging with OpenIdConnect. RedirectUri: {RedirectUri}",
         props.RedirectUri
      );

      // Triggers OIDC challenge (redirect to authorization server).
      return Challenge(props, OpenIdConnectDefaults.AuthenticationScheme);
   }

   /// <summary>
   /// Initiates the OIDC logout flow.
   ///
   /// Important:
   /// - The OIDC logout uses a TECHNICAL callback endpoint (RedirectUri) where the middleware
   ///   finishes the protocol flow.
   /// - The final UX destination ("/") is handled by SignedOut().
   /// </summary>
   /// <returns>Empty result (OIDC middleware performs the redirect to the auth server).</returns>
   // [HttpGet("logout")]
   // public async Task<IActionResult> Logout() {
   //    logger.LogInformation("Logout requested for user: {User}", User.Identity?.Name ?? "(anonymous)");
   //
   //    // After the OIDC middleware completed the sign-out callback,
   //    // it will redirect the browser to this final UX destination.
   //    var props = new AuthenticationProperties {
   //       RedirectUri = "/"
   //    };
   //
   //    // Step 1: end local session (remove the authentication cookie for this client app)
   //    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
   //
   //    // Step 2: trigger OIDC end-session (redirect to authorization server)
   //    await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, props);
   //    
   //    
   //    // The OIDC middleware will handle the redirect to the authorization server.
   //    return new EmptyResult();
   //    
   // }
   
   [HttpGet("logout")]
   public IActionResult Logout()
   {
      return SignOut(
         new AuthenticationProperties { RedirectUri = "/" },
         OpenIdConnectDefaults.AuthenticationScheme,
         CookieAuthenticationDefaults.AuthenticationScheme
      );
   }


   // /// <summary>
   // /// Technical callback endpoint after OIDC logout.
   // ///
   // /// This endpoint should not render UI.
   // /// It only redirects to the final UX destination inside the client app.
   // /// </summary>
   // [HttpGet("signed-out")]
   // public IActionResult SignedOut() {
   //    logger.LogInformation("Signed-out callback reached. Redirecting to '/'.");
   //
   //    // Final user-facing destination after logout:
   //    return LocalRedirect("/");
   // }
}

/*
===============================================================================
DIDAKTIK & LERNZIELE (DE)
===============================================================================

0) Warum gibt es einen "Signed-Out Callback"?
---------------------------------------------
OIDC trennt strikt zwischen:
- TECHNISCHEN Callback-Endpunkten (für Middleware/Protokoll)
- und UX-Zielseiten (für Menschen)

Bei Logout ist RedirectUri NICHT die Zielseite, sondern der Rückkanal,
über den die OIDC-Middleware den Logout abschließt.

Merksatz:
   "Callback ist Technik – Redirect ist UX."

-------------------------------------------------------------------------------

1) Controller statt Minimal API für Auth-Flows
----------------------------------------------
Vorteile eines Controllers:
- klare Bündelung der Auth-Routen (/identity/*)
- gute Testbarkeit (Controller-Unit-Tests)
- weniger Routing-Konflikte mit Blazor
- didaktisch: "Auth ist kritisch → explizit implementieren"

-------------------------------------------------------------------------------

2) Login-Flow (Challenge) richtig lesen
---------------------------------------
Challenge() bedeutet:
- User ist nicht authentifiziert
- Redirect zum Authorization Server (/connect/authorize)
- nach erfolgreichem Login: Redirect zurück zur RedirectUri im Client

Wichtig:
- returnUrl IM Client muss lokal sein (Url.IsLocalUrl)
- sonst drohen Open Redirects

-------------------------------------------------------------------------------

3) Logout-Flow: drei Stationen (statt "nur Cookie löschen")
-----------------------------------------------------------
A) Lokale Client-Session beenden:
   - CookieAuthenticationDefaults (Client-App Cookie)

B) Zentrale SSO-Session beenden:
   - OpenIdConnectDefaults (EndSession beim AuthServer)

C) Technischer Rückkanal im Client:
   - /identity/signed-out
   - hier erst finaler Redirect auf "/" (oder Login)

Warum C)?
Weil sonst der Browser nach Logout auf einer technischen Callback-URL stehen bleibt
(z.B. /signout-callback-oidc), die für den User nicht als "Startseite" gedacht ist.

-------------------------------------------------------------------------------

4) Begriffsklärung: RedirectUri vs SignedOutCallbackPath vs PostLogoutRedirectUri
--------------------------------------------------------------------------------
- RedirectUri (Client, Login): Ziel im Client nach erfolgreichem Login.
- SignedOutCallbackPath (Client, Logout): technische Callback-Route im Client.
- PostLogoutRedirectUri (AuthServer, Client-Registrierung): wohin der AuthServer
  nach Logout zurückleiten DARF (Whitelist).

Merksatz:
   "PostLogoutRedirectUri wird im AuthServer registriert, SignedOutCallbackPath ist im Client."

-------------------------------------------------------------------------------

5) Lernziele für Studierende
----------------------------
Studierende sollen verstehen:
- OIDC ist ein Protokollfluss (nicht nur UI)
- Logout ist sicherheitskritisch (SSO + Redirects)
- Callback-Endpunkte sind technische Bausteine
- Open Redirect Prevention (Url.IsLocalUrl) ist Pflicht
- Trennung von Verantwortung: Middleware (Protokoll) vs App (Navigation/UX)

-------------------------------------------------------------------------------

6) Übungs-/Testideen
--------------------
A) Open Redirect Test:
   /identity/login?returnUrl=https://evil.com
   → darf NICHT extern redirecten

B) Logout ohne OIDC SignOut:
   Schritt 2 auskommentieren → SSO bleibt aktiv → sofort wieder eingeloggt

C) Callback verstehen:
   SignedOut() loggt und redirectet auf "/" → UX sauber

===============================================================================
*/