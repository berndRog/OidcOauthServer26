using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OidcOauthServer.Infrastructure.Identity;
namespace OidcOauthServer.Infrastructure.Persistence;

public sealed class AuthDbContext
   : IdentityDbContext<ApplicationUser, IdentityRole, string> {
   
   public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) {
   }

   protected override void OnModelCreating(ModelBuilder builder) {
      base.OnModelCreating(builder);

      // Adds OpenIddict entity mappings to the same database
      builder.UseOpenIddict();
   }
}