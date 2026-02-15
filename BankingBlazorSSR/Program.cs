using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using BankingBlazorSsr.Api.Auth;
using BankingBlazorSsr.Api.Clients;
using BankingBlazorSsr.Api.Contracts;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
namespace BankingBlazorSsr;

public sealed class Program {
   public static void Main(string[] args) {
      var builder = WebApplication.CreateBuilder(args);
      
      //--- Logging, HTTP Logging ----------------------------------------------
      ConfigureLoginng(builder, builder.Services);

      //--- Configure services and modules -------------------------------------
      // Blazor SSR with interactive server components
      ConfigureBlazorSSR(builder.Services, builder.Configuration);
      // OIDC Authentication (Cookie + OpenID Connect)
      ConfigureAuthN(builder.Services, builder.Configuration, builder.Environment);
      // Authorization policies (OwnersOnly, EmployeesOnly)
      ConfigureAuthZ(builder.Services);

      // -----------------------------------------------------------------------
      // Middleware pipeline configuration
      var app = builder.Build();
      if (!app.Environment.IsDevelopment()) {
         app.UseExceptionHandler("/Error", createScopeForErrors: true);
         app.UseHsts();
      }

      // HTTP logging middleware (useful during development/troubleshooting)
      // app.UseHttpLogging();

      // Security middlewares
      app.UseHttpsRedirection();
      
      // Serve static files (e.g., CSS, JS, images)
      app.UseStaticFiles();

      // Routing must be before auth middlewares and endpoint mapping
      // neede for /indentity/login and /identity/logout endpoints in IdentityController
      app.UseRouting();
      
      // Authentication and Authorization middlewares
      app.UseAuthentication();
      app.UseAuthorization();
      // Antiforgery middleware for CSRF protection (important for state-changing endpoints)
      app.UseAntiforgery();

      // -----------------------------------------------------------------------------
      // Endpoints
      // -----------------------------------------------------------------------------
      // Controller-Routes (Login/Logout via IdentityController)
      app.MapControllers();

      // Blazor SSR components
      // so we use regular server-rendered Razor components without
      app.MapRazorComponents<App>()
         .AddInteractiveServerRenderMode();

      app.Run();
   }

   /// <summary>
   /// Configure logging providers and HTTP logging options.
   /// </summary>
   /// <param name="builder"></param>
   /// <param name="services"></param>
   private static void ConfigureLoginng( 
      WebApplicationBuilder builder, 
      IServiceCollection services
   ) {
      builder.Logging.ClearProviders();
      builder.Logging.AddConsole();
      builder.Logging.AddDebug();
      
      services.AddHttpLogging(o => {
         o.LoggingFields =
            HttpLoggingFields.RequestMethod |
            HttpLoggingFields.RequestPath |
            HttpLoggingFields.RequestQuery |
            HttpLoggingFields.RequestHeaders |
            HttpLoggingFields.ResponseStatusCode |
            HttpLoggingFields.ResponseHeaders;
      
         // Optional: bodies (DEV only). Be careful: can leak sensitive data.
         o.LoggingFields |=
            HttpLoggingFields.RequestBody |
            HttpLoggingFields.ResponseBody;
      
         // DEV only: logging Authorization header will print bearer tokens.
         // NEVER enable this in production.
         o.RequestHeaders.Add("Authorization");
         o.MediaTypeOptions.AddText("application/json");
      });
   }
   
   /// <summary>
   /// Configure Blazor Server-Side Rendering (SSR) with interactive server components.
   /// </summary>
   private static void ConfigureBlazorSSR(
      IServiceCollection services,
      IConfiguration configuration
   ) {
      //--- Blazor SSR (Core Services) / Infrastructure ------------------------
      // Server-Side Rendering (SSR) with interactive components
      // Razor components rendered on the server
      services
         .AddRazorComponents()
         .AddInteractiveServerComponents();
      
      // Needed to access HttpContext (e.g., for token retrieval in handlers)
      services.AddHttpContextAccessor();

      // Enables <AuthorizeView> and cascading authentication state in components
      services.AddCascadingAuthenticationState();

      //--- MVC Controllers / Presentation  -------------------------------------
      // we implement /identity/login, /identity/logout as controller actions
      services.AddControllers();
      
      //--- JSON options for API clients -----------------------------------------
      services.AddSingleton(new JsonSerializerOptions {
         WriteIndented = true,  // pretty-print for easier debugging (optional)
         PropertyNameCaseInsensitive = true,
         ReadCommentHandling = JsonCommentHandling.Skip,
         AllowTrailingCommas = true,
         NumberHandling = JsonNumberHandling.AllowReadingFromString,
         DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
         Converters = { new JsonStringEnumConverter() }
      });
      
      //--- Typed HTTP client for the Banking API / Communication ----------------
      // AccessTokenHandler attaches the access token to each request.
      services.AddTransient<AccessTokenHandler>();

      services.AddHttpClient("BankingApi", client => { 
         client.BaseAddress = new Uri(configuration["BankingApi:BaseUrl"]!);
         client.Timeout = TimeSpan.FromSeconds(30);
      })
      .AddHttpMessageHandler<AccessTokenHandler>();

      services.AddScoped<IOwnerClient,OwnerClient>();
      services.AddScoped<IEmployeeClient,EmployeeClient>();
      services.AddScoped<IAccountClient, AccountClient>();
   }
   
   /// <summary>
   /// Configure OpenID Connect authentication with cookies as local session store.
   /// </summary>
   private static void ConfigureAuthN(
      IServiceCollection services,
      IConfiguration config,
      IWebHostEnvironment enviroment
   ) {
      var auth = config.GetSection("AuthServer");

      // DEV-only diagnostics: verify that secrets are loaded
      Console.WriteLine(
         $"SSR ClientId={auth["ClientId"]}, SecretPresent={!string.IsNullOrWhiteSpace(auth["ClientSecret"])}"
      );

      services
         .AddAuthentication(options => {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
         })
         .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => {
            // Cookie holds the authenticated session for SSR
            options.SlidingExpiration = true;
         })
         .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options => {
            // OIDC authority (issuer base URL)
            options.Authority = auth["Authority"]!;

            // Confidential client credentials
            options.ClientId = auth["ClientId"]!;
            options.ClientSecret = auth["ClientSecret"]!;

            // Authorization Code Flow
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.UsePkce = true;
            
            // Callback endpoints in this SSR app
            options.CallbackPath = auth["CallbackPath"] ?? "/signin-oidc";
            options.SignedOutCallbackPath =
               auth["SignedOutCallbackPath"] ?? "/signout-callback-oidc";
            options.SignedOutRedirectUri = "/";   // 
            
            // Keep tokens in the auth session (cookie ticket)
            options.SaveTokens = true;

            // Optional: fetch additional user claims from /connect/userinfo
            options.GetClaimsFromUserInfoEndpoint = true;

            // Requested scopes (must match what the AuthServer has seeded/allowed)
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("offline_access"); // for refresh tokens
            options.Scope.Add(auth["ApiScope"] ?? "banking_api");

            // Map name and roles to your claim types
            options.TokenValidationParameters = new TokenValidationParameters {
               NameClaimType = "preferred_username", 
               RoleClaimType = ClaimTypes.Role 
//               RoleClaimType = "role"
            };
            
            //options.RequireHttpsMetadata = true;
            options.RequireHttpsMetadata = !enviroment.IsDevelopment();
            
            // Events for debugging
            options.Events = new OpenIdConnectEvents {
               OnRedirectToIdentityProvider = context => {
                  var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                  logger.LogInformation("Redirecting to identity provider: {Issuer}", context.ProtocolMessage.IssuerAddress);
                  return Task.CompletedTask;
               },
               OnRemoteFailure = context => {
                  var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                  logger.LogError(context.Failure, "Remote authentication failure");
                  context.Response.Redirect("/error");
                  context.HandleResponse();
                  return Task.CompletedTask;
               },
               OnAuthenticationFailed = context => {
                  var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                  logger.LogError(context.Exception, "Authentication failed");
                  return Task.CompletedTask;
               }
            };
         });
   }

   /// <summary>
   /// Configure authorization policies used by components and endpoints.
   /// </summary>
   private static void ConfigureAuthZ(IServiceCollection services) {
      services.AddAuthorization(options => {
         options.AddPolicy("OwnersOnly", policy => policy.RequireRole("Owner"));
         options.AddPolicy("EmployeesOnly", policy => policy.RequireRole("Employee"));
      });
   }
}

/*
===============================================================================
DIDAKTIK & LERNZIELE (DE)
===============================================================================

1) SSR + OIDC: klare Verantwortlichkeiten
----------------------------------------
- Cookie = lokale Session im SSR-Frontend (Browser <-> SSR-App)
- OpenID Connect = Login-Protokoll und Token-Beschaffung (SSR-App <-> AuthServer)
- Access Token = Aufrufe an die Banking API (SSR-App -> BankingApi)

Merksatz:
   Cookie hält "eingeloggt", Access Token erlaubt "API-Zugriff".

2) Warum SaveTokens = true?
---------------------------
Die SSR-App benötigt das Access Token später, um die BankingApi aufzurufen.
Mit SaveTokens werden die Tokens im Auth-Ticket (Cookie) gespeichert und
können z.B. über einen AccessTokenHandler ausgelesen werden.

3) Claims vs Rollen vs Rechte
-----------------------------
- role (Claim) dient der technischen Autorisierung in ASP.NET (Policies/Roles).
- account_type (Claim) ist fachlich/domänennah (Owner/Employee/Service).
- admin_rights (Claim) ist fein-granular (Bitmask für Employee-Berechtigungen).

Merksatz:
   role = "wo darf ich hin", admin_rights = "was darf ich genau", account_type = "wer bin ich fachlich".

4) Policies statt if-Spaghetti
------------------------------
Policies kapseln Regeln zentral:
- OwnersOnly / EmployeesOnly sind wiederverwendbar in Components/Endpoints.
Das hält UI und API sauber und testbar.

5) HTTP Logging: mächtig, aber gefährlich
-----------------------------------------
Authorization-Header/Token zu loggen ist nur in DEV sinnvoll.
In PROD wäre das ein Sicherheitsproblem (Token Leakage).

Übungsidee:
- Studierende sollen einmal absichtlich zu viele Daten ins Token legen
  und anschließend diskutieren, warum "Datenminimierung" wichtig ist.

===============================================================================
*/