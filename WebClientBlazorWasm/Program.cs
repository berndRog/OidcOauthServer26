using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using WebClientBlazorWasm;
var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");

// Config aus wwwroot/appsettings.json
var authSection = builder.Configuration.GetSection("AuthServer");
var authority = authSection["Authority"] ?? "https://localhost:7001";
var clientId = authSection["ClientId"] ?? "blazor-wasm";
var scopes = authSection.GetSection("Scopes").Get<string[]>() ?? new[] { "openid" };

// Default HttpClient
builder.Services.AddHttpClient("WebClientBlazorWasm",
   client => { client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress); });

// OIDC
builder.Services.AddOidcAuthentication(options => {
   options.ProviderOptions.Authority = authority.TrimEnd('/');
   options.ProviderOptions.ClientId = clientId;
   options.ProviderOptions.ResponseType = "code"; // Code + PKCE

   options.ProviderOptions.DefaultScopes.Add("openid");
   options.ProviderOptions.DefaultScopes.Add("profile");
   options.ProviderOptions.DefaultScopes.Add("api");
});

await builder.Build().RunAsync();