using System.Security.Claims;
using BankingBlazorSSR.Api.Clients;
using BankingBlazorSSR.Auth;
using BankingBlazorSSR.UseCases.OwnerProfile;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
namespace BankingBlazorSSR;

public sealed class Program {
   public static void Main(string[] args) {
      var builder = WebApplication.CreateBuilder(args);

      // -----------------------------------------------------------------------
      // Logging, HTTP Logging
      // -----------------------------------------------------------------------
      builder.Logging.ClearProviders();
      builder.Logging.AddConsole();
      builder.Logging.AddDebug();

      builder.Services.AddHttpLogging(o => {
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

      // -----------------------------------------------------------------------
      // Configure services and modules
      // -----------------------------------------------------------------------
      ConfigureBlazorSSR(builder.Services, builder.Configuration);

      ConfigureAuthN(builder.Services, builder.Configuration);
      ConfigureAuthZ(builder.Services);

      // -----------------------------------------------------------------------
      // Middleware
      // -----------------------------------------------------------------------
      var app = builder.Build();
      if (!app.Environment.IsDevelopment()) {
         app.UseExceptionHandler("/Error", createScopeForErrors: true);
         app.UseHsts();
      }

      // HTTP logging middleware (useful during development/troubleshooting)
      app.UseHttpLogging();

      app.UseHttpsRedirection();
      app.UseStaticFiles();

      // Routing must be before auth middlewares and endpoint mapping
      // neede for /indentity/login and /identity/logout endpoints in IdentityController
      app.UseRouting();
      
      app.UseAuthentication();
      app.UseAuthorization();
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
      
      //--- Typed HTTP client for the Banking API / Communication ----------------
      // AccessTokenHandler attaches the access token to each request.
      services.AddTransient<AccessTokenHandler>();

      services.AddHttpClient("BankingApi",
         client => {
            client.BaseAddress = new Uri(configuration["BankingApi:BaseUrl"]!);
         })
        .AddHttpMessageHandler<AccessTokenHandler>();

      services.AddScoped<OwnersClient>(sp => {
         var http = sp.GetRequiredService<IHttpClientFactory>()
            .CreateClient("BankingApi");
         return new OwnersClient(http);
      });

      //-- Use Cases / Application ----------------------------------------------
      services.AddScoped<PostOwnerProvision>();
      services.AddScoped<GetOwnerProfile>();
      services.AddScoped<UpdateOwnerProfile>();
   }

   /// <summary>
   /// Configure OpenID Connect authentication with cookies as local session store.
   /// </summary>
   private static void ConfigureAuthN(
      IServiceCollection services,
      IConfiguration config
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

            // Callback endpoints in this SSR app
            options.CallbackPath = auth["CallbackPath"] ?? "/signin-oidc";
            options.SignedOutCallbackPath =
               auth["SignedOutCallbackPath"] ?? "/signout-callback-oidc";
            options.SignedOutRedirectUri = "/";   // 

            
            Console.WriteLine($"CallbackPath={options.CallbackPath}, SignedOutCallbackPath={options.SignedOutCallbackPath}");

            options.Events ??= new OpenIdConnectEvents();
            options.Events.OnSignedOutCallbackRedirect = context => {
               // Final UX destination after the technical callback
               context.Response.Redirect("/");
               context.HandleResponse();
               return Task.CompletedTask;
            };

            
            // Keep tokens in the auth session (cookie ticket)
            options.SaveTokens = true;

            // Optional: fetch additional user claims from /connect/userinfo
            options.GetClaimsFromUserInfoEndpoint = true;

            // Requested scopes (must match what the AuthServer has seeded/allowed)
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add(auth["ApiScope"] ?? "banking_api");

            // Map name and roles to your claim types
            options.TokenValidationParameters = new TokenValidationParameters {
               NameClaimType = "preferred_username",
               RoleClaimType = ClaimTypes.Role
            };
            
            options.RequireHttpsMetadata = true;
            
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