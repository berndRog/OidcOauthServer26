using System.Security.Claims;
using OidcOauthServer.Data;
namespace OidcOauthServer.Auth.Claims;

public static class AdminRightsExtensions {
   
   // ClaimsPrincipal extension methods for working with AdminRights claim
   public static AdminRights GetAdminRights(this ClaimsPrincipal user) {
      var raw = user.FindFirst(AuthClaims.AdminRights)?.Value;
      return int.TryParse(raw, out var value)
         ? (AdminRights)value
         : AdminRights.None;
   }

   public static bool HasRight(this ClaimsPrincipal user, AdminRights required)
      => (user.GetAdminRights() & required) == required;

   public static bool IsAdmin(this ClaimsPrincipal user)
      => user.GetAdminRights() != AdminRights.None;
}

