using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OidcOauthServer.Auth.Options;
using OidcOauthServer.Auth.Seeding;
using OidcOauthServer.Infrastructure.Identity;
using OidcOauthServer.Infrastructure.Persistence;

namespace OidcOauthServer;

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
         Origin(authServer.BlazorWasm.BaseUrl), // https://localhost:6010
         Origin(authServer.WebMvc.BaseUrl) // https://localhost:6020 (optional)
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

      app.UseAuthentication();
      app.UseAuthorization();

      // Bind CORS to endpoints for maximum reliability (especially /.well-known and /connect/*)
      app.MapControllers().RequireCors("Frontends");
      app.MapDefaultControllerRoute().RequireCors("Frontends");
      app.MapRazorPages().RequireCors("Frontends");
      
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
         .AddServer(o => {
            // Issuer / Authority
            o.SetIssuer(new Uri(auth.IssuerUri, UriKind.Absolute));

            // Endpoints as paths
            o.SetAuthorizationEndpointUris("/" + AuthServerOptions.AuthorizationEndpointPath)
               .SetTokenEndpointUris("/" + AuthServerOptions.TokenEndpointPath)
               .SetUserInfoEndpointUris("/" + AuthServerOptions.UserInfoEndpointPath)
               .SetEndSessionEndpointUris("/" + AuthServerOptions.LogoutEndpointPath)
               .SetConfigurationEndpointUris("/" + AuthServerOptions.ConfigurationEndpointPath);

            // Flows
            o.AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow();

            // PKCE required for public clients
            o.RequireProofKeyForCodeExchange();

            // Scopes (standard + configured API scopes)
            o.RegisterScopes(
               new[] { "openid", "profile" }
                  .Concat(auth.Apis.Values.Select(a => a.Scope))
                  .Distinct(StringComparer.Ordinal)
                  .ToArray()
            );
            
            // Dev certs
            o.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

            if (!auth.Tokens.EncryptAccessTokens)
               o.DisableAccessTokenEncryption();

            // ASP.NET Core integration
            o.UseAspNetCore()
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

// using Microsoft.AspNetCore.Authentication.Cookies;
// using Microsoft.AspNetCore.HttpLogging;
// using Microsoft.AspNetCore.Identity;
// using Microsoft.EntityFrameworkCore;
// using OidcOauthServer.Auth.Options;
// using OidcOauthServer.Auth.Seeding;
// using OidcOauthServer.Infrastructure.Identity;
// using OidcOauthServer.Infrastructure.Persistence;
// namespace OidcOauthServer;
//
// public class Program {
//    public static void Main(string[] args) {
//       var builder = WebApplication.CreateBuilder(args);
//
//       // ----------------------------
//       // Logging
//       // ----------------------------
//       builder.Logging.ClearProviders();
//       builder.Logging.AddConsole();
//       builder.Logging.AddDebug();
//
//       // ----------------------------
//       // Options binding (appsettings + user-secrets + env vars)
//       // ----------------------------
//       builder.Services
//          .AddOptions<AuthServerOptions>()
//          .Bind(builder.Configuration.GetSection(AuthServerOptions.SectionName))
//          .Validate(o => Uri.TryCreate(o.IssuerUri, UriKind.Absolute, out _),
//             "AuthServer:IssuerUri must be a valid absolute URI.")
//          .ValidateOnStart();
//
//       builder.Services.Configure<AuthServerOptions>(
//          builder.Configuration.GetSection("AuthServer")
//       );
//
//       // We also resolve a snapshot once for OpenIddict configuration (no secrets required here).
//       var authServer = builder.Configuration
//          .GetSection(AuthServerOptions.SectionName)
//          .Get<AuthServerOptions>(); // ?? new AuthServerOptions();
//
//       // ----------------------------
//       // Services
//       // ----------------------------
//       //builder.Services.AddHttpLogging(o => o.LoggingFields = HttpLoggingFields.All);
//       builder.Services.AddHttpLogging(o => {
//          o.LoggingFields =
//             HttpLoggingFields.RequestPropertiesAndHeaders |
//             HttpLoggingFields.RequestBody |
//             HttpLoggingFields.ResponsePropertiesAndHeaders |
//             HttpLoggingFields.ResponseBody;
//
//          // Bodies werden sonst gern abgeschnitten:
//          o.RequestBodyLogLimit = 2048;
//          o.ResponseBodyLogLimit = 2028;
//
//          // Achtung: bei Auth niemals dauerhaft aktiv lassen
//          o.CombineLogs = true;
//       });
//
//       ConfigureDatabase(builder.Services, builder.Configuration, builder.Environment);
//       ConfigureIdentity(builder.Services);
//       ConfigureOpenIddict(builder.Services, authServer);
//       ConfigureMvcAndUi(builder.Services);
//
//       // Seed demo user + standard clients (Blazor, Android, Service)
//       builder.Services.AddHostedService<SeedUsersHostedService>();
//       builder.Services.AddHostedService<SeedHostedService>();
//
//       // CORS for Blazor WASM client
//       var allowedOrigins = new[] {
//          Origin(authServer.BlazorWasm.BaseUrl), // https://localhost:6010
//          Origin(authServer.WebMvc.BaseUrl) // https://localhost:6020
//       };
//
//       builder.Services.AddCors(options => {
//          options.AddPolicy("Frontends", policy => {
//             policy.WithOrigins(allowedOrigins)
//                .AllowAnyHeader()
//                .AllowAnyMethod()
//                .AllowCredentials();
//          });
//       });
//
//       var app = builder.Build();
//
//       // ----------------------------
//       // HTTP pipeline
//       // ----------------------------
//       if (app.Environment.IsDevelopment())
//          app.UseDeveloperExceptionPage();
//
//       app.UseHttpsRedirection();
//       app.UseStaticFiles();
//
//       app.UseRouting();
//       app.UseCors("Frontends");
//
//       app.UseHttpLogging();
//
//       app.UseAuthentication();
//       app.UseAuthorization();
//
//       app.MapControllers();
//
//       // Standard MVC route (optional)
//       app.MapDefaultControllerRoute();
//
//       // Identity UI pages
//       app.MapRazorPages();
//
//       app.Run();
//    }
//
//    static string Origin(string url) {
//       var uri = new Uri(url, UriKind.Absolute);
//       return uri.GetLeftPart(UriPartial.Authority); // https://localhost:6010
//    }
//
//    //-- Service configuration --------------------------------------------------
//    private static void ConfigureDatabase(
//       IServiceCollection services,
//       IConfiguration config,
//       IWebHostEnvironment env
//    ) {
//       // Single SQLite DB for Identity + OpenIddict (simple & local-friendly)
//       var dbName = config.GetConnectionString("OAuthDb") ?? "openidauth1.0.db";
//
//       var dbFile = Path.Combine(env.ContentRootPath, dbName);
//       var sqlite = $"Data Source={dbFile}";
//       Console.WriteLine(sqlite);
//
//       services.AddDbContext<AuthDbContext>(options => {
//          options.UseSqlite(sqlite);
//
//          // Required for OpenIddict EF Core integration
//          options.UseOpenIddict();
//       });
//    }
//
//    private static void ConfigureIdentity(
//       IServiceCollection services
//    ) {
//       services
//          .AddIdentity<ApplicationUser, IdentityRole>()
//          .AddEntityFrameworkStores<AuthDbContext>()
//          .AddDefaultTokenProviders()
//          .AddDefaultUI();
//
//       // services.ConfigureApplicationCookie(o => {
//       //    // Redirect unauthenticated users here (Razor UI)
//       //    o.LoginPath = "/Identity/Account/Login";
//       //    o.AccessDeniedPath = "/Identity/Account/AccessDenied";
//       //
//       //    // IMPORTANT:
//       //    // - Browser/HTML navigation (OIDC) must get a 302 redirect to the login UI
//       //    // - API/Ajax calls should get 401/403 instead of HTML redirects
//       //    o.Events = new CookieAuthenticationEvents {
//       //       OnRedirectToLogin = ctx => {
//       //          var accept = ctx.Request.Headers.Accept.ToString();
//       //          var wantsHtml = accept.Contains("text/html", StringComparison.OrdinalIgnoreCase);
//       //
//       //          if (wantsHtml) {
//       //             ctx.Response.Redirect(ctx.RedirectUri);
//       //          }
//       //          else {
//       //             ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
//       //          }
//       //
//       //          return Task.CompletedTask;
//       //       },
//       //       OnRedirectToAccessDenied = ctx => {
//       //          var accept = ctx.Request.Headers.Accept.ToString();
//       //          var wantsHtml = accept.Contains("text/html", StringComparison.OrdinalIgnoreCase);
//       //
//       //          if (wantsHtml) {
//       //             ctx.Response.Redirect(ctx.RedirectUri);
//       //          }
//       //          else {
//       //             ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
//       //          }
//       //
//       //          return Task.CompletedTask;
//       //       }
//       //    };
//       // });
//       // Identity cookie is the default for interactive browser flows
//       // services.AddAuthentication(options => {
//       //    options.DefaultScheme = IdentityConstants.ApplicationScheme;
//       //    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
//       // });
//
//       services.ConfigureApplicationCookie(o => {
//          o.LoginPath = "/Identity/Account/Login";
//          o.AccessDeniedPath = "/Identity/Account/AccessDenied";
//
//          o.Events = new CookieAuthenticationEvents {
//             OnRedirectToLogin = ctx => {
//                if (IsOidcOrIdentityEndpoint(ctx.Request)) {
//                   ctx.Response.Redirect(ctx.RedirectUri);
//                   return Task.CompletedTask;
//                }
//                if (WantsJson(ctx.Request)) {
//                   ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
//                   return Task.CompletedTask;
//                }
//                ctx.Response.Redirect(ctx.RedirectUri);
//                return Task.CompletedTask;
//             },
//
//             OnRedirectToAccessDenied = ctx => {
//                if (IsOidcOrIdentityEndpoint(ctx.Request)) {
//                   ctx.Response.Redirect(ctx.RedirectUri);
//                   return Task.CompletedTask;
//                }
//                if (WantsJson(ctx.Request)) {
//                   ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
//                   return Task.CompletedTask;
//                }
//                ctx.Response.Redirect(ctx.RedirectUri);
//                return Task.CompletedTask;
//             }
//          };
//       });
//
//       // Identity cookie is the default for interactive browser flows
//       services.AddAuthentication(options => {
//          options.DefaultScheme = IdentityConstants.ApplicationScheme;
//          options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
//       });
//
//       services.AddAuthorization();
//    }
//
//    private static void ConfigureOpenIddict(
//       IServiceCollection services,
//       AuthServerOptions auth
//    ) {
//       services.AddOpenIddict()
//
//          // OpenIddict Core (EF storage)
//          .AddCore(o => {
//             o.UseEntityFrameworkCore()
//                .UseDbContext<AuthDbContext>();
//          })
//
//          // OpenIddict Server
//          .AddServer(o => {
//             // Issuer / Authority (must match client configuration)
//             o.SetIssuer(auth.Issuer);
//
//             // OpenIddict expects endpoint URIs as *paths*.
//             o.SetAuthorizationEndpointUris("/" + AuthServerOptions.AuthorizationEndpointPath)
//                .SetTokenEndpointUris("/" + AuthServerOptions.TokenEndpointPath)
//                .SetUserInfoEndpointUris("/" + AuthServerOptions.UserInfoEndpointPath)
//                .SetEndSessionEndpointUris("/" + AuthServerOptions.LogoutEndpointPath)
//                .SetConfigurationEndpointUris("/" + AuthServerOptions.ConfigurationEndpointPath);
//
//             // Supported flows
//             o.AllowAuthorizationCodeFlow()
//                .AllowClientCredentialsFlow();
//
//             // PKCE is mandatory for public clients
//             o.RequireProofKeyForCodeExchange();
//
//             // Scopes
//             o.RegisterScopes("openid", "profile", auth.ScopeApi);
//
//             // Dev certificates only (for production use real certs)
//             o.AddDevelopmentEncryptionCertificate()
//                .AddDevelopmentSigningCertificate();
//
//             // Access Token Encryption from appsettings
//             if (!auth.Tokens.EncryptAccessTokens) {
//                // Access tokens will be plain JWT (JWS),
//                // readable with jwt.io – ideal for teaching/debugging
//                o.DisableAccessTokenEncryption();
//             }
//
//             // Enable ASP.NET Core host integration
//             o.UseAspNetCore()
//                .EnableUserInfoEndpointPassthrough()
//                .EnableAuthorizationEndpointPassthrough();
//             //    .EnableTokenEndpointPassthrough()
//             //    .EnableUserInfoEndpointPassthrough()
//             //    .EnableEndSessionEndpointPassthrough();
//          })
//
//          // ----------------------------
//          // OpenIddict Validation (resource server)
//          // ----------------------------
//          .AddValidation(o => {
//             // Validate tokens issued by THIS server
//             o.UseLocalServer();
//             o.UseAspNetCore();
//          });
//    }
//
//    private static void ConfigureMvcAndUi(IServiceCollection services) {
//       // Controllers are needed for [ApiController] endpoints (/connect/*, /dev/*)
//       // services.AddControllers(); redundant if using AddControllersWithViews()
//       services.AddControllersWithViews(); // Views/Shared/*
//       services.AddRazorPages(); // Identity UI (/Areas/Identity/...)
//    }
//
//    private static bool WantsJson(HttpRequest req) {
//       var accept = req.Headers.Accept.ToString();
//       if (accept.Contains("application/json", StringComparison.OrdinalIgnoreCase)) return true;
//
//       // typische Ajax-Indikatoren
//       var xrw = req.Headers["X-Requested-With"].ToString();
//       if (xrw.Equals("XMLHttpRequest", StringComparison.OrdinalIgnoreCase)) return true;
//
//       return false;
//    }
//
//
//    private static bool IsOidcOrIdentityEndpoint(HttpRequest req) {
//       var path = req.Path.Value ?? "";
//       return path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase)
//          || path.StartsWith("/.well-known/", StringComparison.OrdinalIgnoreCase)
//          || path.StartsWith("/Identity/", StringComparison.OrdinalIgnoreCase);
//    }
// }