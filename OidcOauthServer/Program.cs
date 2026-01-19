using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OidcOauthServer.Auth.Options;
using OidcOauthServer.Auth.Seeding;
using OidcOauthServer.Infrastructure.Identity;
using OidcOauthServer.Infrastructure.Persistence;
namespace OidcOauthServer;

public class Program {
   
   public static void Main(string[] args) {
      var builder = WebApplication.CreateBuilder(args);

      // ----------------------------
      // Logging
      // ----------------------------
      builder.Logging.ClearProviders();
      builder.Logging.AddConsole();
      builder.Logging.AddDebug();

      // ----------------------------
      // Options binding (appsettings + user-secrets + env vars)
      // ----------------------------
      builder.Services
         .AddOptions<AuthServerOptions>()
         .Bind(builder.Configuration.GetSection(AuthServerOptions.SectionName))
         .Validate(o => Uri.TryCreate(o.IssuerUri, UriKind.Absolute, out _),
            "AuthServer:IssuerUri must be a valid absolute URI.")
         .ValidateOnStart();

      // We also resolve a snapshot once for OpenIddict configuration (no secrets required here).
      var auth = builder.Configuration
         .GetSection(AuthServerOptions.SectionName)
         .Get<AuthServerOptions>() ?? new AuthServerOptions();

      // ----------------------------
      // Services
      // ----------------------------
      //builder.Services.AddHttpLogging(o => o.LoggingFields = HttpLoggingFields.All);
      builder.Services.AddHttpLogging(o => {
         o.LoggingFields =
            HttpLoggingFields.RequestPropertiesAndHeaders |
            HttpLoggingFields.RequestBody |
            HttpLoggingFields.ResponsePropertiesAndHeaders |
            HttpLoggingFields.ResponseBody;

         // Bodies werden sonst gern abgeschnitten:
         o.RequestBodyLogLimit = 2048;
         o.ResponseBodyLogLimit = 2028;

         // Achtung: bei Auth niemals dauerhaft aktiv lassen
         o.CombineLogs = true;
      });

      ConfigureDatabase(builder.Services, builder.Configuration, builder.Environment);
      ConfigureIdentity(builder.Services);
      ConfigureOpenIddict(builder.Services, auth);
      ConfigureMvcAndUi(builder.Services);

      // Seed demo user + standard clients (Blazor, Android, Service)
      builder.Services.AddHostedService<SeedUsersHostedService>();
      builder.Services.AddHostedService<SeedHostedService>();
      

      var app = builder.Build();

      // ----------------------------
      // Pipeline
      // ----------------------------
      ConfigureMiddleware(app);
      MapEndpoints(app);

      app.Run();
   }

   //-- Service configuration --------------------------------------------------
   private static void ConfigureDatabase(
      IServiceCollection services,
      IConfiguration config,
      IWebHostEnvironment env
   ) {
      // Single SQLite DB for Identity + OpenIddict (simple & local-friendly)
      var dbName = config.GetConnectionString("OAuthDb") ?? "openidauth1.0.db";

      var dbFile = Path.Combine(env.ContentRootPath, dbName);
      var sqlite = $"Data Source={dbFile}";
      Console.WriteLine(sqlite);

      services.AddDbContext<AuthDbContext>(options => {
         options.UseSqlite(sqlite);

         // Required for OpenIddict EF Core integration
         options.UseOpenIddict();
      });
   }

   private static void ConfigureIdentity(IServiceCollection services) {
      services
         .AddIdentity<ApplicationUser, IdentityRole>()
         .AddEntityFrameworkStores<AuthDbContext>()
         .AddDefaultTokenProviders()
         .AddDefaultUI();

      services.ConfigureApplicationCookie(o => {
         // Redirect unauthenticated users here (Razor UI)
         o.LoginPath = "/Identity/Account/Login";
         o.AccessDeniedPath = "/Identity/Account/AccessDenied";

         // IMPORTANT:
         // - Browser/HTML navigation (OIDC) must get a 302 redirect to the login UI
         // - API/Ajax calls should get 401/403 instead of HTML redirects
         o.Events = new CookieAuthenticationEvents {
            OnRedirectToLogin = ctx => {
               var accept = ctx.Request.Headers.Accept.ToString();
               var wantsHtml = accept.Contains("text/html", StringComparison.OrdinalIgnoreCase);

               if (wantsHtml) {
                  ctx.Response.Redirect(ctx.RedirectUri);
               }
               else {
                  ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
               }

               return Task.CompletedTask;
            },
            OnRedirectToAccessDenied = ctx => {
               var accept = ctx.Request.Headers.Accept.ToString();
               var wantsHtml = accept.Contains("text/html", StringComparison.OrdinalIgnoreCase);

               if (wantsHtml) {
                  ctx.Response.Redirect(ctx.RedirectUri);
               }
               else {
                  ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
               }

               return Task.CompletedTask;
            }
         };
      });

      // Identity cookie is the default for interactive browser flows
      services.AddAuthentication(options => {
         options.DefaultScheme = IdentityConstants.ApplicationScheme;
         options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
      });

      services.AddAuthorization();
   }

   private static void ConfigureOpenIddict(IServiceCollection services, AuthServerOptions auth) {
      services.AddOpenIddict()

         // OpenIddict Core (EF storage)
         .AddCore(o => {
            o.UseEntityFrameworkCore()
               .UseDbContext<AuthDbContext>();
         })

         // OpenIddict Server
         .AddServer(o => {
            // Issuer / Authority (must match client configuration)
            o.SetIssuer(auth.Issuer);

            // OpenIddict expects endpoint URIs as *paths*.
            o.SetAuthorizationEndpointUris("/" + AuthServerOptions.AuthorizationEndpointPath)
               .SetTokenEndpointUris("/" + AuthServerOptions.TokenEndpointPath)
               .SetUserInfoEndpointUris("/" + AuthServerOptions.UserInfoEndpointPath)
               .SetEndSessionEndpointUris("/" + AuthServerOptions.LogoutEndpointPath)
               .SetConfigurationEndpointUris("/" + AuthServerOptions.ConfigurationEndpointPath);

            // Supported flows
            o.AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow();

            // PKCE is mandatory for public clients
            o.RequireProofKeyForCodeExchange();

            // Scopes
            o.RegisterScopes("openid", "profile", auth.ScopeApi);

            // Dev certificates only (for production use real certs)
            o.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

            // Enable ASP.NET Core host integration
            o.UseAspNetCore()
               .EnableUserInfoEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough();
            //    .EnableTokenEndpointPassthrough()
            //    .EnableUserInfoEndpointPassthrough()
            //    .EnableEndSessionEndpointPassthrough();
         })

         // ----------------------------
         // OpenIddict Validation (resource server)
         // ----------------------------
         .AddValidation(o => {
            // Validate tokens issued by THIS server
            o.UseLocalServer();
            o.UseAspNetCore();
         });
   }

   private static void ConfigureMvcAndUi(IServiceCollection services) {
      // Controllers are needed for [ApiController] endpoints (/connect/*, /dev/*)
      // services.AddControllers(); redundant if using AddControllersWithViews()
      services.AddControllersWithViews(); // Views/Shared/*
      services.AddRazorPages(); // Identity UI (/Areas/Identity/...)
   }

   // ----------------------------
   // HTTP pipeline
   // ----------------------------
   private static void ConfigureMiddleware(WebApplication app) {
      if (app.Environment.IsDevelopment())
         app.UseDeveloperExceptionPage();

      app.UseHttpsRedirection();
      app.UseStaticFiles();

      app.UseRouting();

      app.UseHttpLogging();

      app.UseAuthentication();
      app.UseAuthorization();
   }

   private static void MapEndpoints(WebApplication app) {
      // REQUIRED for attribute routing controllers:
      app.MapControllers();

      // Standard MVC route (optional)
      app.MapDefaultControllerRoute();

      // Identity UI pages
      app.MapRazorPages();
   }
}