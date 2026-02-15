using IdentityAccessServer.Data;
using Microsoft.AspNetCore.Identity;
namespace IdentityAccessServer.Infrastructure.Identity;

/// <summary>
/// Identity user entity (ASP.NET Core Identity).
///
/// This class stores authentication-related data
/// plus identity profile attributes that are exposed
/// as OpenID Connect claims.
///
/// This is intentionally pragmatic and course-friendly:
/// OpenIddict can directly emit these values into tokens.
///
/// In a later phase, these concerns can be split into
/// a dedicated Accounts/Auth bounded context.
/// </summary>
public sealed class ApplicationUser : IdentityUser {
   /*
    * IdentityUser already has 
      Id (string GUID)
      UserName
      Email, NormalizedEmail
      PasswordHash
      SecurityStamp, ConcurrencyStamp
      Lockout/2FA usw.
    */
   
   // ------------------------------------------------------------------
   // Account classification
   // ------------------------------------------------------------------
   /// <summary>
   /// "customer", "owner", or "employee".
   /// - customer: self-registered, normal access
   /// - owner: self-registered, needs activation by employee (has Status field)
   /// - employee: managed account with AdminRights
   /// </summary>
   public string AccountType { get; set; } = "owner";
   
   // ------------------------------------------------------------------
   // Administrative rights (bitmask)
   // ------------------------------------------------------------------
   /// <summary>
   /// Administrative permissions stored as a bitmask enum.
   /// Backed by an int column in the database.
   /// </summary>
   public AdminRights AdminRights { get; set; } = AdminRights.None;
   
   // ------------------------------------------------------------------
   // OIDC profile claims ("profile" scope)
   // ------------------------------------------------------------------
   /// <summary>
   /// When the account was created (registration completed).
   /// Immutable.
   /// </summary>
   public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

   /// <summary>
   /// Last meaningful activity timestamp.
   /// Updated on login, password change, or profile update.
   /// </summary>
   public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
/*
Didactic goals:
   - Understand the responsibility of ApplicationUser in ASP.NET Identity
   - Learn which data belongs to identity vs. domain models
   - See how OIDC profile claims are persisted and emitted
   - Avoid premature bounded-context splitting in early phases
   
   Learning outcomes:
   - Students can design a pragmatic Identity model
   - Students can map Identity fields to OIDC claims
   - Students understand why roles are optional and often redundant
   - Students learn when and why refactoring into a dedicated Auth BC makes sense
  
  
  
  Wie erkennst du damit zuverlässig „Leichen“?
   Szenario	                              CreatedAt   UpdatedAt	   Interpretation
   User registriert, nie eingeloggt	      alt	      ≈ CreatedAt	   Leiche (nie benutzt)
   User registriert, einmal eingeloggt	   alt	      später	      legitimer Account
   User lange inaktiv	                  alt	      sehr alt	      evtl. Leiche / Archiv
   Employee-Account	                     egal	      egal	         niemals automatisch löschen
   
*/





