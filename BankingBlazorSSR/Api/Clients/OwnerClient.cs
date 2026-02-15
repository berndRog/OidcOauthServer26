using System.Text.Json;
using BankingBlazorSsr.Api.Contracts;
using BankingBlazorSsr.Api.Dtos;
using BankingBlazorSsr.Core;
namespace BankingBlazorSsr.Api.Clients;

public sealed class OwnerClient(
   IHttpClientFactory factory,
   JsonSerializerOptions json,
   ILogger<OwnerClient> logger
) : BaseApiClient<OwnerClient>(factory, json, logger), IOwnerClient
{
   private const string Base = "bankingapi/v1";

   // POST bankingapi/v1/owners/me/provisioned  -> 200 OK + OwnerProvisionDto
   public Task<Result<ProvisionDto>> PostProvisionAsync(CancellationToken ct = default) 
      => SendAsync<ProvisionDto>(
         () => _http.PostAsync($"{Base}/owners/me/provisioned", content: null, ct), ct);

   // GET bankingapi/v1/owners/me/profile -> 200 OK + OwnerProfileDto
   public Task<Result<OwnerDto>> GetProfileAsync(CancellationToken ct = default) 
      => SendAsync<OwnerDto>(() => _http.GetAsync($"{Base}/owners/me/profile", ct), ct);

   // PUT bankingapi/v1/owners/me/profile -> 200 OK + OwnerProfileDto
   public Task<Result<OwnerDto>> UpdateProfileAsync(
      OwnerDto dto,
      CancellationToken ct = default
   ) => SendAsync<OwnerDto>(
         () => _http.PutAsJsonAsync($"{Base}/owners/me/profile", dto, ct), ct);

   // GET /owners
   public Task<Result<IEnumerable<OwnerDto>>> GetAllAsync(CancellationToken ct = default) 
      => SendAsync<IEnumerable<OwnerDto>>(
         () => _http.GetAsync($"{Base}/owners", ct), ct);

   // GET /owners/{ownerId}
   public Task<Result<OwnerDto>> GetByIdAsync(Guid ownerId, CancellationToken ct = default) 
      => SendAsync<OwnerDto>(
         () => _http.GetAsync($"{Base}/owners/{ownerId}", ct), ct);

   // GET /owners/username/?username={userName}
   public Task<Result<OwnerDto>> GetByUserNameAsync(string userName, CancellationToken ct = default) 
      => SendAsync<OwnerDto>(
         () => _http.GetAsync($"{Base}/owners/username/?username={Uri.EscapeDataString(userName)}", ct), ct);

   // GET /owners/name/?name={name}
   public Task<Result<IEnumerable<OwnerDto>>> GetByNameAsync(string name, CancellationToken ct = default) 
      => SendAsync<IEnumerable<OwnerDto>>(
         () => _http.GetAsync($"{Base}/owners/name/?name={Uri.EscapeDataString(name)}", ct),ct);

   // GET /owners/exists/?username={userName} -> bool body
   public Task<Result<bool>> ExistsByUserNameAsync(string userName, CancellationToken ct = default) 
      => SendAsync<bool>(
         () => _http.GetAsync($"{Base}/owners/exists/?username={Uri.EscapeDataString(userName)}", ct), ct);
}
