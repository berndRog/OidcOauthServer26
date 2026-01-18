using Microsoft.AspNetCore.Identity;

namespace OidcOauthServer.Data;

/// <summary>
/// Identity user entity (ASP.NET Core Identity).
///
/// This is a pragmatic course-friendly approach:
/// we store minimal domain references + rights here
/// so OpenIddict can emit them as token claims.
///
/// Later (Phase 2), you can move these to an Auth/Accounts BC
/// and keep Identity purely technical.
/// </summary>
public sealed class ApplicationUser : IdentityUser
{
   /// <summary>
   /// "customer" or "employee" (kept as string to stay simple in the UI and DB).
   /// </summary>
   public string AccountType { get; set; } = "customer";

   /// <summary>
   /// Domain reference id for Customer (only set when AccountType == "customer").
   /// </summary>
   public Guid? CustomerId { get; set; }

   /// <summary>
   /// Domain reference id for Employee (only set when AccountType == "employee").
   /// </summary>
   public Guid? EmployeeId { get; set; }

   /// <summary>
   /// Employee-only rights bitmask stored as int (AdminRights enum flags).
   /// </summary>
   public int? AdminRights { get; set; }
}

/*
DE:
- ApplicationUser ist hier "kursfreundlich" erweitert:
  AccountType + CustomerId/EmployeeId + AdminRights (int Bitmaske).
- Damit kann der AuthServer diese Werte direkt als Claims in Access Tokens schreiben.
- Später kann man das sauber in einen Auth/Accounts-BC auslagern.
*/
