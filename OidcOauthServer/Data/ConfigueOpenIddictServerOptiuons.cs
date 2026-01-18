using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OidcOauthServer.Data;
using OpenIddict.Server;

namespace OidcOauthServer.Data;

public static class OpenIddictServerBuilderExtensions
{
   public static OpenIddictServerBuilder ConfigureFromAuthServerOptions(
      this OpenIddictServerBuilder builder,
      IServiceCollection services)
   {
      // We can safely build a minimal provider here ONLY to read options at startup.
      // If you want to avoid this entirely, pass AuthServerOptions in from Program.cs.
      using var sp = services.BuildServiceProvider();
      var auth = sp.GetRequiredService<IOptions<AuthServerOptions>>().Value;

      builder.SetIssuer(auth.Issuer);

      // OpenIddict expects endpoint URIs as *paths*.
      builder.SetAuthorizationEndpointUris("/" + AuthServerOptions.AuthorizationEndpointPath)
         .SetTokenEndpointUris("/" + AuthServerOptions.TokenEndpointPath)
         .SetUserInfoEndpointUris("/" + AuthServerOptions.UserInfoEndpointPath)
         .SetEndSessionEndpointUris("/" + AuthServerOptions.LogoutEndpointPath);

      builder.AllowAuthorizationCodeFlow()
         .AllowClientCredentialsFlow();

      builder.RequireProofKeyForCodeExchange();

      builder.RegisterScopes("openid", "profile", auth.ScopeApi);

      builder.AddDevelopmentEncryptionCertificate()
         .AddDevelopmentSigningCertificate();

      return builder;
   }
}