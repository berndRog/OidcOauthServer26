namespace OidcOauthServer.Auth.Claims;

/// <summary>
/// Central definition of all claim types issued by the AuthServer.
///
/// This class is the single source of truth for:
/// - OIDC standard claims
/// - Profile-related claims
/// - Domain-specific authorization and lifecycle claims
///
/// Clients (MVC, Blazor WASM, Android, APIs) must rely on these constants.
/// </summary>
public static class AuthClaims {
   //--- Standard OIDC / JWT claims -------------------------------------------
   /// <summary>
   /// Subject identifier (OIDC mandatory).
   /// Stable technical identity of the user.
   /// </summary>
   public const string Subject = "sub";

   /// <summary>
   /// User email address.
   /// Used as primary login identifier for customers.
   /// </summary>
   public const string Email = "email";

   /// <summary>
   /// Human-readable username for UI purposes.
   /// Typically equal to email in this system.
   /// </summary>
   public const string PreferredUsername = "preferred_username";

   //--- Domain-specific claims -------------------------------------------
   /// <summary>
   /// Account classification.
   /// Values: "customer" | "employee"
   /// </summary>
   public const string AccountType = "account_type";

   /// <summary>
   /// Employee authorization bitmask.
   /// Serialized enum value (int).
   /// </summary>
   public const string AdminRights = "admin_rights";

   //--- Lifecycle / housekeeping claims -------
   /// <summary>
   /// Account creation timestamp (UTC, ISO-8601).
   /// Used to detect abandoned or stale accounts.
   /// </summary>
   public const string CreatedAt = "created_at";

   /// <summary>
   /// Last meaningful activity timestamp (UTC, ISO-8601).
   /// Updated on login or profile changes.
   /// </summary>
   public const string UpdatedAt = "updated_at";
}

// public static class AuthClaims {
//    // Standard (OIDC / JWT)
//    public const string Subject = "sub";
//    public const string Email = "email";
//    public const string Name = "name";
//
//    // Profile (OIDC "profile" scope)
//    public const string GivenName = "given_name";
//    public const string FamilyName = "family_name";
//    public const string Birthdate = "birthdate";
//    public const string Gender = "gender";
//    public const string PreferredUsername = "preferred_username";
//
//    // Custom (domain-specific)
//    public const string AccountType = "account_type";   // customer | employee
//    public const string AdminRights = "admin_rights";   // int bitmask
// }
