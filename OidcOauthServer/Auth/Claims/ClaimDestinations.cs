using System.Security.Claims;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcOauthServer.Auth.Claims;

/// <summary>
/// Central mapping that controls which claims go into which token.
/// - AccessToken: for APIs (authorization, domain checks)
/// - IdentityToken: for clients (UI display, basic identity info)
/// </summary>
public static class ClaimDestinations {
   public static IEnumerable<string> GetDestinations(
      Claim claim,
      ClaimsPrincipal principal
   ) {
      // -----------------------------------------------------------------------      
      // IdentityToken
      // -----------------------------------------------------------------------
      // Mandatory OIDC subject
      if (claim.Type == AuthClaims.Subject)
         return new[] { Destinations.AccessToken, Destinations.IdentityToken };

      // Standard identity/profile-like claims
      // NOTE: In our minimal setup we do not maintain given_name/family_name/etc.
      // We only emit email + preferred_username.
      if (claim.Type 
          is AuthClaims.Email 
          // or AuthClaims.Name
          // or AuthClaims.GivenName
          // or AuthClaims.FamilyName
          // or AuthClaims.Birthdate
          // or AuthClaims.Gender
          or AuthClaims.PreferredUsername
      ) return principal.HasScope(Scopes.Profile)
            ? new[] { Destinations.IdentityToken }
            : Array.Empty<string>();
      
      // -----------------------------------------------------------------------      
      // IdentityToken + AccessToken
      // -----------------------------------------------------------------------
      // Lifecycle / housekeeping (debuggable in id_token, usable in API)
      if (claim.Type 
          is AuthClaims.CreatedAt 
          or AuthClaims.UpdatedAt
      ) return new[] { Destinations.AccessToken, Destinations.IdentityToken };
      
      
      // -----------------------------------------------------------------------      
      // AccessToken only
      // -----------------------------------------------------------------------
      // Domain-specific claims → access token only
      if (claim.Type 
          is AuthClaims.AccountType
          or AuthClaims.AdminRights
          //or "customer_id"
          //or "employee_id"
         ) return new[] { Destinations.AccessToken };

      // Everything else is excluded by default
      return Array.Empty<string>();
   }
}
/*
(Didaktik & Lernziele)
-----------------------------------------------------------------------
Ziel:
   - Studierende verstehen, dass Claims nicht "automatisch" in Tokens landen,
      sondern bewusst pro Token-Typ zugewiesen werden (Destinations).

   Merksätze:
1) Access Token = für APIs (Autorisierung, fachliche Checks)
2) ID Token     = für Clients/UI (Anzeige, Login-Kontext)
3) Minimale Profile:
   - Wir geben nur E-Mail + preferred_username als "Profile" aus.
4) AdminRights gehört NICHT in den ID Token:
   - UI kann es aus dem Access Token / API ableiten,
- verhindert unnötige Daten im Browser-Token.

   Übungsidee:
   - Lass die Studierenden testweise AdminRights in den ID Token legen
   und diskutiert anschließend Sicherheits- und Datenminimierungsaspekte.
-----------------------------------------------------------------------
*/










