using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using WebClientBankingBlazorWasm;
var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");

// Config aus wwwroot/appsettings.json
var authSection = builder.Configuration.GetSection("AuthServer");
var authority = authSection["Authority"] 
   ?? throw new InvalidOperationException(
      "Configuration 'AuthServer:Authority' is missing in appsettings.json");

var clientId = authSection["ClientId"] 
   ?? throw new InvalidOperationException(
      "Configuration 'AuthServer:ClientId' is missing in appsettings.json");

var scopes = authSection.GetSection("Scopes").Get<string[]>() 
   ?? throw new InvalidOperationException(
      "Configuration 'AuthServer:Scopes' is missing in appsettings.json");

if (scopes.Length == 0) {
   throw new InvalidOperationException(
      "Configuration 'AuthServer:Scopes' must contain at least one scope");
}

// Default HttpClient
builder.Services.AddHttpClient("WebClientBankingBlazorWasm",
   client => { client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress); });

builder.Services.AddOidcAuthentication(options => {
   options.ProviderOptions.Authority = authority; //"https://localhost:7001";
   options.ProviderOptions.ClientId = clientId; //"blazor-wasm";
   options.ProviderOptions.ResponseType = "code";
   
   options.ProviderOptions.DefaultScopes.Clear();
   foreach (var scope in scopes) {
       options.ProviderOptions.DefaultScopes.Add(scope);
   }  
});

Console.WriteLine("WebClientBankingBlazorWasm starting...");
Console.WriteLine($"AuthServer:Authority={authority}");
Console.WriteLine($"AuthServer:ClientId={clientId}");
Console.WriteLine($"Scopes: {string.Join(", ", scopes)}");

await builder.Build().RunAsync();