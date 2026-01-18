using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using WebClientMvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

var authSection   = builder.Configuration.GetSection("AuthServer");
var authority     = authSection["Authority"] ?? "https://localhost:7001/";
var clientId      = authSection["ClientId"] ?? "webclient-mvc";
var clientSecret  = builder.Configuration["AuthServer:WebMvc:ClientSecret"] ?? "webclient-mvc-secret"; // ✅ dein secret-key
var scopes        = authSection.GetSection("Scopes").Get<string[]>() ?? ["openid"];

Console.WriteLine($"AuthServer:Authority={authority}");
Console.WriteLine($"AuthServer:ClientId={clientId}");
Console.WriteLine($"AuthServer:WebMvc:ClientSecret={clientSecret}");



builder.Services.AddAuthentication(authOpt =>
   {
      authOpt.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
      authOpt.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
   })
   .AddCookie()
   .AddOpenIdConnect(openIdOpt => {
      openIdOpt.Authority = authority.TrimEnd('/');
      openIdOpt.ClientId = clientId;
      openIdOpt.ClientSecret = clientSecret;
      openIdOpt.ResponseType = "code";

      openIdOpt.SaveTokens = true;
      openIdOpt.GetClaimsFromUserInfoEndpoint = true;

      openIdOpt.Scope.Clear();
      foreach (var s in scopes)
         openIdOpt.Scope.Add(s);
   });

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapDefaultControllerRoute();
app.Run();