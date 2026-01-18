using OpenIddict.Validation;

namespace OidcOauthServer.Data;

public static class OpenIddictValidationBuilderExtensions
{
   public static OpenIddictValidationBuilder ConfigureLocalValidation(this OpenIddictValidationBuilder builder)
   {
      builder.UseLocalServer();
      return builder;
   }
}