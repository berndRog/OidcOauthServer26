using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using WebClientBankingBlazorSSR.Hosting;
using WebClientBankingBlazorSSR.Hosting.Clients;
namespace WebClientBankingBlazorSSR;

public sealed class Program {
   public static void Main(string[] args) {
      var builder = WebApplication.CreateBuilder(args);

      ConfigureServices(builder);

      var app = builder.Build();

      ConfigurePipeline(app);

      app.Run();
   }

   private static void ConfigureServices(WebApplicationBuilder builder) {
      
      // Blazor SSR + Interactive Server
      builder.Services
         .AddRazorComponents()
         .AddInteractiveServerComponents();

      // Controllers für /login, /logout
      builder.Services.AddControllers();

      // AuthZ / Auth State
      builder.Services.AddAuthorization();
      builder.Services.AddCascadingAuthenticationState();
      builder.Services.AddHttpContextAccessor();

      ConfigureOidc(builder.Services, builder.Configuration);
      ConfigureBankingApi(builder.Services, builder.Configuration);
   }

   private static void ConfigureOidc(IServiceCollection services, IConfiguration config) {
      var auth = config.GetSection("AuthServer");

      services.AddAuthentication(options => {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
         })
         .AddCookie()
         .AddOpenIdConnect(options => {
            options.Authority = auth["Authority"]!;
            options.ClientId = auth["ClientId"]!;
            options.ClientSecret = auth["ClientSecret"]!;
            options.ResponseType = OpenIdConnectResponseType.Code;

            options.CallbackPath = auth["CallbackPath"] ?? "/signin-oidc";
            options.SignedOutCallbackPath = auth["SignedOutCallbackPath"] ?? "/signout-callback-oidc";

            options.SaveTokens = true;
            options.GetClaimsFromUserInfoEndpoint = true;

            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");
            options.Scope.Add(auth["ApiScope"] ?? "banking_api");

            options.RequireHttpsMetadata = true;
         });
   }

   private static void ConfigureBankingApi(IServiceCollection services, IConfiguration config) {
      services.AddTransient<AccessTokenHandler>();

      services.AddHttpClient("BankingApi", client => { client.BaseAddress = new Uri(config["BankingApi:BaseUrl"]!); })
         .AddHttpMessageHandler<AccessTokenHandler>();

      services.AddScoped<OwnersClient>(sp => {
         var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient("BankingApi");
         return new OwnersClient(http);
      });
   }

   private static void ConfigurePipeline(WebApplication app) {
      // Template-typisch
      if (!app.Environment.IsDevelopment()) {
         app.UseExceptionHandler("/Error", createScopeForErrors: true);
         app.UseHsts();
      }

      app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

      app.UseHttpsRedirection();

      // .NET 10 Template nutzt oft MapStaticAssets statt UseStaticFiles
      app.MapStaticAssets();

      app.UseAntiforgery();

      // Auth muss vor Endpoints
      app.UseAuthentication();
      app.UseAuthorization();

      // Controller Endpoints
      app.MapControllers();

      // Blazor
      app.MapRazorComponents<App>()
         .AddInteractiveServerRenderMode();
   }
}