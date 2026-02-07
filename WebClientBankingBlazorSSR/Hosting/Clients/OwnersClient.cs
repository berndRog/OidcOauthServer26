using System.Net;
using System.Net.Http.Json;
using WebClientBankingBlazorSSR.Hosting.Dtos;
namespace WebClientBankingBlazorSSR.Hosting.Clients;

public sealed class OwnersClient(HttpClient http) {
   
   // BaseAddress kommt aus DI (BankingApi:BaseUrl)
   private const string ProvisionedUrl = "api/owners/me/provisioned";
   private const string ProfileUrl     = "api/owners/me/profile";

   public async Task<OwnerMeDto> GetMeProvisionedAsync(CancellationToken ct = default) {
      var response = await http.GetAsync(ProvisionedUrl, ct);

      if (response.StatusCode == HttpStatusCode.Unauthorized)
         throw new UnauthorizedAccessException("Not authenticated / token missing.");

      response.EnsureSuccessStatusCode();

      return (await response.Content.ReadFromJsonAsync<OwnerMeDto>(cancellationToken: ct))
         ?? throw new InvalidOperationException("Empty response body.");
   }

   public async Task<OwnerProfileDto> GetMeProfileAsync(CancellationToken ct = default) {
      var response = await http.GetAsync(ProfileUrl, ct);

      if (response.StatusCode == HttpStatusCode.Unauthorized)
         throw new UnauthorizedAccessException("Not authenticated / token missing.");

      response.EnsureSuccessStatusCode();

      return (await response.Content.ReadFromJsonAsync<OwnerProfileDto>(cancellationToken: ct))
         ?? throw new InvalidOperationException("Empty response body.");
   }
}
