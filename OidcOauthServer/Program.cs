// // using Microsoft.AspNetCore.HttpLogging;
// // using Microsoft.AspNetCore.Identity;
// // using Microsoft.EntityFrameworkCore;
// // using OpenIddict.Validation.AspNetCore;
// // using OidcOauthServer.Data;
// //
// // namespace OidcOauthServer;
// //
// // /// <summary>
// // /// Entry point of the OAuth2 / OpenID Connect Authorization Server.
// // ///
// // /// Hosts:
// // /// - ASP.NET Core Identity (Razor Pages UI, cookie-based login)
// // /// - OpenIddict Server (/connect/* protocol endpoints)
// // ///
// // /// Protocol strings (URLs/scopes/client ids) live in AuthServerDefaults.
// // /// </summary>
// // public class Program {
// //
// //    public static void Main(string[] args) {
// //
// //       var builder = WebApplication.CreateBuilder(args);
// //
// //       // ----------------------------
// //       // Logging
// //       // ----------------------------
// //       builder.Logging.ClearProviders();
// //       builder.Logging.AddConsole();
// //       builder.Logging.AddDebug();
// //
// //       // ----------------------------
// //       // Services
// //       // ----------------------------
// //       builder.Services.AddHttpLogging(opts => {
// //          opts.LoggingFields = HttpLoggingFields.All;
// //       });
// //
// //       ConfigureDatabase(builder.Services, builder.Configuration, builder.Environment);
// //       ConfigureIdentity(builder.Services);
// //       ConfigureOpenIddict(builder.Services);
// //       ConfigureMvcAndUi(builder.Services);
// //
// //       // Seed demo user + standard clients (Blazor, Android, Service)
// //       builder.Services.AddHostedService<SeedHostedService>();
// //
// //       var app = builder.Build();
// //
// //       // ----------------------------
// //       // Pipeline
// //       // ----------------------------
// //       ConfigureMiddleware(app);
// //       MapEndpoints(app);
// //
// //       app.Run();
// //    }
// //
// //    // ----------------------------
// //    // Service configuration
// //    // ----------------------------
// //
// //    private static void ConfigureDatabase(
// //       IServiceCollection services,
// //       IConfiguration config,
// //       IWebHostEnvironment env
// //    ) {
// //       // Single SQLite DB for Identity + OpenIddict (simple & local-friendly)
// //       var dbName = config.GetConnectionString("OAuthDb") ?? "openidauth1.0.db";
// //
// //       var dbFile = Path.Combine(env.ContentRootPath, dbName);
// //       var sqlite = $"Data Source={dbFile}";
// //       Console.WriteLine(sqlite);
// //
// //       services.AddDbContext<AuthDbContext>(options => {
// //          options.UseSqlite(sqlite);
// //
// //          // Optional but nice: OpenIddict expects this for EF Core integration
// //          options.UseOpenIddict();
// //       });
// //    }
// //
// //    private static void ConfigureIdentity(IServiceCollection services) {
// //
// //       services
// //          .AddIdentity<ApplicationUser, IdentityRole>(options => {
// //             // Optional: keep defaults or tighten password policy
// //             // options.Password.RequireNonAlphanumeric = false;
// //          })
// //          .AddEntityFrameworkStores<AuthDbContext>()
// //          .AddDefaultTokenProviders()
// //          .AddDefaultUI();
// //
// //       // Redirect unauthenticated users here (Razor UI)
// //       services.ConfigureApplicationCookie(o => {
// //          o.LoginPath = AuthServerDefaults.IdentityLoginPath;
// //       });
// //    }
// //
// //    private static void ConfigureOpenIddict(IServiceCollection services) {
// //
// //       // "Smart" default:
// //       // - Bearer token present => OpenIddict Validation scheme
// //       // - otherwise => Identity cookie (browser / Razor Pages)
// //       services.AddAuthentication(options => {
// //          options.DefaultScheme = IdentityConstants.ApplicationScheme;
// //          options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
// //       });
// //
// //       services.AddAuthorization();
// //
// //       services.AddOpenIddict()
// //          // ----------------------------
// //          // OpenIddict Core (EF storage)
// //          // ----------------------------
// //          .AddCore(o => {
// //             o.UseEntityFrameworkCore()
// //              .UseDbContext<AuthDbContext>();
// //          })
// //
// //          // ----------------------------
// //          // OpenIddict Server
// //          // ----------------------------
// //          .AddServer(o => {
// //
// //             // Issuer / Authority (must match client configuration)
// //             o.SetIssuer(AuthServerDefaults.Issuer);
// //
// //             // Protocol endpoints
// //             o.SetAuthorizationEndpointUris(AuthServerDefaults.AuthorizationEndpoint)
// //              .SetTokenEndpointUris(AuthServerDefaults.TokenEndpoint)
// //              .SetUserInfoEndpointUris(AuthServerDefaults.UserInfoEndpoint)
// //              .SetEndSessionEndpointUris(AuthServerDefaults.EndSessionEndpoint);
// //
// //             // Supported flows
// //             o.AllowAuthorizationCodeFlow()
// //              .AllowClientCredentialsFlow();
// //
// //             // PKCE is mandatory for public clients
// //             o.RequireProofKeyForCodeExchange();
// //
// //             // Scopes
// //             o.RegisterScopes(
// //                AuthServerDefaults.ScopeOpenId,
// //                AuthServerDefaults.ScopeProfile,
// //                AuthServerDefaults.ScopeApi);
// //
// //             // Dev certificates only (for production use real certs)
// //             o.AddDevelopmentEncryptionCertificate()
// //              .AddDevelopmentSigningCertificate();
// //
// //             // Enable ASP.NET Core host integration
// //             o.UseAspNetCore()
// //              .EnableAuthorizationEndpointPassthrough()
// //              .EnableTokenEndpointPassthrough()
// //              .EnableUserInfoEndpointPassthrough()
// //              .EnableEndSessionEndpointPassthrough();
// //
// //             // Optional: if you want refresh tokens
// //             // o.AllowRefreshTokenFlow();
// //          })
// //
// //          // ----------------------------
// //          // OpenIddict Validation (resource server)
// //          // ----------------------------
// //          .AddValidation(o => {
// //             // Validate tokens issued by THIS server
// //             o.UseLocalServer();
// //             o.UseAspNetCore();
// //          });
// //    }
// //
// //    private static void ConfigureMvcAndUi(IServiceCollection services) {
// //       // /connect/* (if you have controllers) + any API endpoints
// //       // services.AddControllers();
// //       services.AddControllersWithViews(); // <-- wichtig für /Views/Shared/*
// //       services.AddRazorPages();           // <-- wichtig für Identity UI (/Areas/Identity/...)
// //    }
// //
// //    // ----------------------------
// //    // HTTP pipeline
// //    // ----------------------------
// //    private static void ConfigureMiddleware(WebApplication app) {
// //
// //       if (app.Environment.IsDevelopment()) {
// //          app.UseDeveloperExceptionPage();
// //       }
// //
// //       app.UseHttpsRedirection();
// //       app.UseStaticFiles();
// //
// //       app.UseRouting();
// //
// //       app.UseHttpLogging();   // <-- IMPORTANT: enables AddHttpLogging()
// //
// //       app.UseAuthentication();
// //       app.UseAuthorization();
// //    }
// //
// //    private static void MapEndpoints(WebApplication app) {
// //       // app.MapControllers();
// //       app.MapDefaultControllerRoute(); // <-- Standard MVC Route
// //       app.MapRazorPages();            // <-- Identity UI Pages
// //    }
// // }
// using Microsoft.AspNetCore.HttpLogging;
// using Microsoft.AspNetCore.Identity;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Options;
// using OidcOauthServer.Data;
//
// namespace OidcOauthServer;
//
// public class Program
// {
//    public static void Main(string[] args)
//    {
//       var builder = WebApplication.CreateBuilder(args);
//
//       builder.Logging.ClearProviders();
//       builder.Logging.AddConsole();
//       builder.Logging.AddDebug();
//
//       // Options binding
//       builder.Services
//          .AddOptions<AuthServerOptions>()
//          .Bind(builder.Configuration.GetSection(AuthServerOptions.SectionName))
//          .Validate(o => Uri.TryCreate(o.IssuerUri, UriKind.Absolute, out _), "AuthServer:IssuerUri must be a valid absolute URI.")
//          .ValidateOnStart();
//
//       builder.Services.AddHttpLogging(o => o.LoggingFields = HttpLoggingFields.All);
//
//       ConfigureDatabase(builder.Services, builder.Configuration, builder.Environment);
//       ConfigureIdentity(builder.Services);
//       ConfigureOpenIddict(builder.Services);
//       ConfigureMvcAndUi(builder.Services);
//
//       builder.Services.AddHostedService<SeedHostedService>();
//
//       var app = builder.Build();
//
//       ConfigureMiddleware(app);
//       MapEndpoints(app);
//
//       app.Run();
//    }
//
//    private static void ConfigureDatabase(IServiceCollection services, IConfiguration config, IWebHostEnvironment env)
//    {
//       var dbName = config.GetConnectionString("OAuthDb") ?? "openidauth1.0.db";
//       var dbFile = Path.Combine(env.ContentRootPath, dbName);
//       var sqlite = $"Data Source={dbFile}";
//       Console.WriteLine(sqlite);
//
//       services.AddDbContext<AuthDbContext>(options =>
//       {
//          options.UseSqlite(sqlite);
//          options.UseOpenIddict();
//       });
//    }
//
//    private static void ConfigureIdentity(IServiceCollection services)
//    {
//       services
//          .AddIdentity<ApplicationUser, IdentityRole>()
//          .AddEntityFrameworkStores<AuthDbContext>()
//          .AddDefaultTokenProviders()
//          .AddDefaultUI();
//
//       services.ConfigureApplicationCookie(o =>
//       {
//          // (kannst du optional auch in Options ziehen, aber muss nicht)
//          o.LoginPath = "/Identity/Account/Login";
//       });
//    }
//
//    private static void ConfigureOpenIddict(IServiceCollection services)
//    {
//       services.AddAuthentication(options =>
//       {
//          options.DefaultScheme = IdentityConstants.ApplicationScheme;
//          options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
//       });
//
//       services.AddAuthorization();
//
//       services.AddOpenIddict()
//          .AddCore(o =>
//          {
//             o.UseEntityFrameworkCore()
//              .UseDbContext<AuthDbContext>();
//          })
//          .AddServer(o =>
//          {
//             // We read options from DI
//             using var sp = services.BuildServiceProvider();
//             var auth = sp.GetRequiredService<IOptions<AuthServerOptions>>().Value;
//
//             o.SetIssuer(auth.Issuer);
//
//             // IMPORTANT: OpenIddict expects *paths* here, not absolute URLs.
//             o.SetAuthorizationEndpointUris("/" + AuthServerOptions.AuthorizationEndpointPath)
//              .SetTokenEndpointUris("/" + AuthServerOptions.TokenEndpointPath)
//              .SetUserInfoEndpointUris("/" + AuthServerOptions.UserInfoEndpointPath)
//              .SetEndSessionEndpointUris("/" + AuthServerOptions.LogoutEndpointPath);
//
//             o.AllowAuthorizationCodeFlow()
//              .AllowClientCredentialsFlow();
//
//             o.RequireProofKeyForCodeExchange();
//
//             o.RegisterScopes("openid", "profile", auth.ScopeApi);
//
//             o.AddDevelopmentEncryptionCertificate()
//              .AddDevelopmentSigningCertificate();
//
//             o.UseAspNetCore()
//              .EnableAuthorizationEndpointPassthrough()
//              .EnableTokenEndpointPassthrough()
//              .EnableUserInfoEndpointPassthrough()
//              .EnableEndSessionEndpointPassthrough();
//          })
//          .AddValidation(o =>
//          {
//             o.UseLocalServer();
//             o.UseAspNetCore();
//          });
//    }
//
//    private static void ConfigureMvcAndUi(IServiceCollection services)
//    {
//       services.AddControllersWithViews();
//       services.AddRazorPages();
//    }
//
//    private static void ConfigureMiddleware(WebApplication app)
//    {
//       if (app.Environment.IsDevelopment())
//          app.UseDeveloperExceptionPage();
//
//       app.UseHttpsRedirection();
//       app.UseStaticFiles();
//
//       app.UseRouting();
//
//       app.UseHttpLogging();
//
//       app.UseAuthentication();
//       app.UseAuthorization();
//    }
//
//    private static void MapEndpoints(WebApplication app)
//    {
//       app.MapDefaultControllerRoute();
//       app.MapRazorPages();
//    }
// }

using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OidcOauthServer.Data;

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
      builder.Services.AddHttpLogging(o =>
      {
         o.LoggingFields =
            HttpLoggingFields.RequestPropertiesAndHeaders |
            HttpLoggingFields.RequestBody |
            HttpLoggingFields.ResponsePropertiesAndHeaders |
            HttpLoggingFields.ResponseBody;

         // Bodies werden sonst gern abgeschnitten:
         o.RequestBodyLogLimit = 4096;
         o.ResponseBodyLogLimit = 4096;

         // Achtung: bei Auth niemals dauerhaft aktiv lassen
         o.CombineLogs = true;
      });

      ConfigureDatabase(builder.Services, builder.Configuration, builder.Environment);
      ConfigureIdentity(builder.Services);
      ConfigureOpenIddict(builder.Services, auth);
      ConfigureMvcAndUi(builder.Services);

      // Seed demo user + standard clients (Blazor, Android, Service)
      builder.Services.AddHostedService<SeedHostedService>();

      var app = builder.Build();

      // ----------------------------
      // Pipeline
      // ----------------------------
      ConfigureMiddleware(app);
      MapEndpoints(app);

      app.Run();
   }

   // ----------------------------
   // Service configuration
   // ----------------------------

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

      // Redirect unauthenticated users here (Razor UI)
      services.ConfigureApplicationCookie(o => { o.LoginPath = "/Identity/Account/Login"; });

      // Cookie is the default for interactive browser flows
      services.AddAuthentication(options => {
         options.DefaultScheme = IdentityConstants.ApplicationScheme;
         options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
      });

      services.AddAuthorization();
   }

   private static void ConfigureOpenIddict(IServiceCollection services, AuthServerOptions auth) {
      services.AddOpenIddict()

         // ----------------------------
         // OpenIddict Core (EF storage)
         // ----------------------------
         .AddCore(o => {
            o.UseEntityFrameworkCore()
               .UseDbContext<AuthDbContext>();
         })

         // ----------------------------
         // OpenIddict Server
         // ----------------------------
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
               .EnableUserInfoEndpointPassthrough();
            //    .EnableAuthorizationEndpointPassthrough()
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
      services.AddControllers();
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