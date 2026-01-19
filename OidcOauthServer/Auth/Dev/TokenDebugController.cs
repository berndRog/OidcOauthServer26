using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace OidcOauthServer.Auth.Dev;

/// <summary>
/// Development-only diagnostic endpoint.
///
/// This controller is used to inspect the authenticated user context
/// after OpenID Connect / OAuth token validation.
///
/// It contains NO business logic and MUST NOT be enabled in production.
/// </summary>
#if DEBUG
[ApiController]
[Route("_dev")]
public sealed class TokenDebugController : ControllerBase
{
   /// <summary>
   /// Returns information about the authenticated principal.
   ///
   /// Requires a valid access token.
   /// </summary>
   [HttpGet("whoami")]
   [Authorize]
   public IActionResult WhoAmI()
   {
      return Ok(new
      {
         authenticationType = User.Identity?.AuthenticationType,
         isAuthenticated = User.Identity?.IsAuthenticated,
         claims = User.Claims.Select(c => new
         {
            type = c.Type,
            value = c.Value
         })
      });
   }
}
#endif

/*
===============================================================================
DIDAKTIK & LERNZIELE (DE)
===============================================================================

Zweck dieses Controllers
-----------------------
Dieser Controller dient ausschließlich der Entwicklung und Lehre.
Er ermöglicht es, den finalen Sicherheitskontext (ClaimsPrincipal)
nach erfolgreicher Token-Validierung sichtbar zu machen.

Er ist bewusst:
- fachlich leer
- technisch minimal
- klar vom Produktivcode getrennt


Lernziele
---------
1. Verständnis der OIDC-/OAuth-Rollen
   - Identity Provider (OIDC Server) stellt Tokens aus
   - Resource Server validiert Tokens
   - Controller arbeitet ausschließlich mit Claims

2. Sichtbarkeit von Claims
   - Welche Claims kommen wirklich im API an?
   - Unterschied zwischen:
     - Identity Token
     - Access Token
   wird praktisch nachvollziehbar

3. Vorbereitung auf Authorization
   - Basis für Policies (RequireClaim, RequireAssertion)
   - Grundlage für AuthorizationHandler (z.B. AdminRights Bitmask)
   - Verständnis: Authorization ≠ Authentication

4. Debugging-Kompetenz
   - Tokens unabhängig von Fachlogik prüfen
   - Fehler klar eingrenzen:
     - Token fehlt
     - Token ungültig
     - Claims fehlen
     - Falsche Scopes / Resources

5. Saubere Architektur
   - Kein Zugriff auf Domain
   - Kein Zugriff auf Use Cases
   - Kein Missbrauch von Controller-Logik


Architektur-Regel
-----------------
Dieser Controller:
- gehört NICHT zur Fachanwendung
- ist KEIN Bestandteil des Security-Modells
- darf NIEMALS für Business-Entscheidungen genutzt werden

Er ist ein Lehr- und Diagnosewerkzeug.
===============================================================================
*/
