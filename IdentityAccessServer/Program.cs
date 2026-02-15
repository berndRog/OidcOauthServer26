using IdentityAccessServer.Auth.Options;
using IdentityAccessServer.Auth.Seeding;
using IdentityAccessServer.Infrastructure.Identity;
using IdentityAccessServer.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityAccessServer;

public static class Program {
   public static void Main(string[] args) {
      
      var builder = WebApplication.CreateBuilder(args);

      // ----------------------------
      // Logging
      // ----------------------------
      builder.Logging.ClearProviders();
      builder.Logging.AddConsole();
      builder.Logging.AddDebug();

      // ----------------------------
      // Options binding + validation
      // ----------------------------
      builder.Services.AddOptions<AuthServerOptions>()
         .Bind(builder.Configuration.GetSection(AuthServerOptions.SectionName))
         .Validate(o => !string.IsNullOrWhiteSpace(o.IssuerUri),
            "AuthServer:IssuerUri is required.")
         .Validate(o => Uri.TryCreate(o.IssuerUri, UriKind.Absolute, out _),
            "AuthServer:IssuerUri must be a valid absolute URI.")
         .ValidateOnStart();


      var authSection = builder.Configuration.GetSection(AuthServerOptions.SectionName);
      if (!authSection.Exists())
         throw new InvalidOperationException($"Missing configuration section '{AuthServerOptions.SectionName}'.");
      var authServer = authSection.Get<AuthServerOptions>()!;
      Console.WriteLine("ENV=" + builder.Environment.EnvironmentName);
      Console.WriteLine("IssuerUri=" + authServer.IssuerUri);
      
      
      // ----------------------------
      // HTTP logging (dev only)
      // ----------------------------
      builder.Services.AddHttpLogging(o => {
         o.LoggingFields =
            HttpLoggingFields.RequestPropertiesAndHeaders |
            HttpLoggingFields.RequestBody |
            HttpLoggingFields.ResponsePropertiesAndHeaders |
            HttpLoggingFields.ResponseBody;

         o.RequestBodyLogLimit = 2048;
         o.ResponseBodyLogLimit = 2048;
         o.CombineLogs = true;
      });

      // ----------------------------
      // Services
      // ----------------------------
      ConfigureDatabase(builder.Services, builder.Configuration, builder.Environment);
      ConfigureIdentity(builder.Services);
      ConfigureOpenIddict(builder.Services, authServer);
      ConfigureMvcAndUi(builder.Services);

      // Seed demo user + standard clients (Blazor, Android, Service)
     
      builder.Services.AddHostedService<SeedUsersHostedService>();
      builder.Services.AddHostedService<SeedHostedService>();

      // ----------------------------
      // CORS (from config)
      // ----------------------------
      var allowedOrigins = new[] {
         Origin(authServer.BlazorWasm.BaseUrl),    // https://localhost:6010
         Origin(authServer.WebMvc.BaseUrl),        // https://localhost:6020 (optional)
         Origin(authServer.WebBlazorSsr.BaseUrl)   // https://localhost:6030 (optional)
      };

      builder.Services.AddCors(options => {
         options.AddPolicy("Frontends", policy => {
            policy.WithOrigins(allowedOrigins)
               .AllowAnyHeader()
               .AllowAnyMethod()
               .AllowCredentials();
         });
      });

      var app = builder.Build();

      // ----------------------------
      // HTTP pipeline
      // ----------------------------
      if (app.Environment.IsDevelopment()) {
         app.UseDeveloperExceptionPage();
         app.UseHttpLogging(); // only in dev
      }

      app.UseHttpsRedirection();
      app.UseStaticFiles();

      app.UseRouting();

      // CORS must be between UseRouting and auth/endpoints.
      app.UseCors("Frontends");

      // Bind CORS to endpoints for maximum reliability (especially /.well-known and /connect/*)
      app.MapControllers().RequireCors("Frontends");
      app.MapDefaultControllerRoute().RequireCors("Frontends");
      app.MapRazorPages().RequireCors("Frontends");

      app.UseAuthentication();
      app.UseAuthorization();

      
      app.Run();
   }

   // -------------------------------------------------------------------------
   // Helpers
   // -------------------------------------------------------------------------
   private static string Origin(string url) {
      var uri = new Uri(url, UriKind.Absolute);
      return uri.GetLeftPart(UriPartial.Authority);
   }

   private static bool WantsJson(HttpRequest req) {
      var accept = req.Headers.Accept.ToString();
      if (accept.Contains("application/json", StringComparison.OrdinalIgnoreCase))
         return true;

      var xrw = req.Headers["X-Requested-With"].ToString();
      if (xrw.Equals("XMLHttpRequest", StringComparison.OrdinalIgnoreCase))
         return true;

      return false;
   }

   private static bool IsOidcOrIdentityEndpoint(HttpRequest req) {
      var path = req.Path.Value ?? "";
      return path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase)
         || path.StartsWith("/.well-known/", StringComparison.OrdinalIgnoreCase)
         || path.StartsWith("/Identity/", StringComparison.OrdinalIgnoreCase);
   }

   // -------------------------------------------------------------------------
   // Service configuration
   // -------------------------------------------------------------------------
   private static void ConfigureDatabase(
      IServiceCollection services,
      IConfiguration config,
      IWebHostEnvironment env) {
      var dbName = config.GetConnectionString("OAuthDb") ?? "openidauth1.0.db";
      var dbFile = Path.Combine(env.ContentRootPath, dbName);
      var sqlite = $"Data Source={dbFile}";

      services.AddDbContext<AuthDbContext>(options => {
         options.UseSqlite(sqlite);
         options.UseOpenIddict();
      });
   }

   private static void ConfigureIdentity(IServiceCollection services) {
      services
         .AddIdentity<ApplicationUser, IdentityRole>()
         .AddEntityFrameworkStores<AuthDbContext>()
         .AddDefaultTokenProviders()
         .AddDefaultUI();

      // Cookie behavior: OIDC/Identity routes must redirect to login UI.
      // Real API calls should return 401/403 instead of HTML.
      services.ConfigureApplicationCookie(o => {
         o.LoginPath = "/Identity/Account/Login";
         o.AccessDeniedPath = "/Identity/Account/AccessDenied";

         o.Events = new CookieAuthenticationEvents {
            OnRedirectToLogin = ctx => {
               if (IsOidcOrIdentityEndpoint(ctx.Request)) {
                  ctx.Response.Redirect(ctx.RedirectUri);
                  return Task.CompletedTask;
               }

               if (WantsJson(ctx.Request)) {
                  ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                  return Task.CompletedTask;
               }

               ctx.Response.Redirect(ctx.RedirectUri);
               return Task.CompletedTask;
            },

            OnRedirectToAccessDenied = ctx => {
               if (IsOidcOrIdentityEndpoint(ctx.Request)) {
                  ctx.Response.Redirect(ctx.RedirectUri);
                  return Task.CompletedTask;
               }

               if (WantsJson(ctx.Request)) {
                  ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                  return Task.CompletedTask;
               }

               ctx.Response.Redirect(ctx.RedirectUri);
               return Task.CompletedTask;
            }
         };
      });

      services.AddAuthorization();
   }

   private static void ConfigureOpenIddict(IServiceCollection services, AuthServerOptions auth) {
      services.AddOpenIddict()

         // Core (EF storage)
         .AddCore(o => {
            o.UseEntityFrameworkCore()
               .UseDbContext<AuthDbContext>();
         })

         // Server
         .AddServer(options => {
            // Issuer / Authority
            options
               .SetIssuer(new Uri(auth.IssuerUri, UriKind.Absolute));

            // Endpoints as paths
            options
               .SetAuthorizationEndpointUris("/" + AuthServerOptions.AuthorizationEndpointPath)
               .SetTokenEndpointUris("/" + AuthServerOptions.TokenEndpointPath)
               .SetUserInfoEndpointUris("/" + AuthServerOptions.UserInfoEndpointPath)
               .SetEndSessionEndpointUris("/" + AuthServerOptions.LogoutEndpointPath)
               .SetConfigurationEndpointUris("/" + AuthServerOptions.ConfigurationEndpointPath);

            // Flows
            options
               .AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow()
               .AllowRefreshTokenFlow();

            // PKCE required for public clients
            options
               .RequireProofKeyForCodeExchange();
            
            // Token lifetimes
            options
               .SetAccessTokenLifetime(TimeSpan.FromMinutes(30));
            options.SetAccessTokenLifetime(TimeSpan.FromMinutes(5));
            

            // Scopes (standard + configured API scopes)
            options
               .RegisterScopes(
                  new[] { "openid", "profile", "offline_access" }
                     .Concat(auth.Apis.Values.Select(a => a.Scope))
                     .Distinct(StringComparer.Ordinal)
                     .ToArray()
               );
            
            // Dev certs
            options
               .AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

            if (!auth.Tokens.EncryptAccessTokens)
               options.DisableAccessTokenEncryption();

            // ASP.NET Core integration
            options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .EnableStatusCodePagesIntegration();
         })

         // Validation (resource server)
         .AddValidation(o => {
            o.UseLocalServer();
            o.UseAspNetCore();
         });
   }

   private static void ConfigureMvcAndUi(IServiceCollection services) {
      services.AddControllersWithViews();
      services.AddRazorPages();
   }
}