using System.Text.Json;
using BankingBlazorSsr.Api.Dtos;
using BankingBlazorSsr.Core;
using BankingBlazorSsr.Core.Dto;
namespace BankingBlazorSsr.Api.Clients;

public sealed class EmployeeClient(
   IHttpClientFactory factory,
   JsonSerializerOptions json,
   ILogger<EmployeeClient> logger
) : BaseApiClient<EmployeeClient>(factory, json, logger)
{
   private const string MeBase = "bankingapi/v1/employee/me";

   // POST bankingapi/v1/owners/me/provisioned  -> 200 OK + OwnerProvisionDto
   public Task<Result<ProvisionDto>> PostProvisionAsync(CancellationToken ct = default) 
      => SendAsync<ProvisionDto>(
         () => _http.PostAsync($"{MeBase}/provisioned", content: null, ct), ct);

   // GET bankingapi/v1/owners/me/profile -> 200 OK + OwnerProfileDto
   public Task<Result<EmployeeDto>> GetProfileAsync(CancellationToken ct = default) 
      => SendAsync<EmployeeDto>(() => _http.GetAsync($"{MeBase}/profile", ct), ct);

   // PUT bankingapi/v1/owners/me/profile -> 200 OK + OwnerProfileDto
   public Task<Result<EmployeeDto>> UpdateProfileAsync(
      OwnerDto dto,
      CancellationToken ct = default
   ) => SendAsync<EmployeeDto>(
         () => _http.PutAsJsonAsync($"{MeBase}/profile", dto, ct), ct);

   // GET /owners
   public Task<Result<IEnumerable<OwnerDto>>> GetAllAsync(CancellationToken ct = default) 
      => SendAsync<IEnumerable<OwnerDto>>(
         () => _http.GetAsync("owners", ct), ct);

   // GET /owners/{ownerId}
   public Task<Result<OwnerDto>> GetByIdAsync(Guid ownerId, CancellationToken ct = default) 
      => SendAsync<OwnerDto>(
         () => _http.GetAsync($"owners/{ownerId}", ct), ct);

   // GET /owners/username/?username={userName}
   public Task<Result<OwnerDto>> GetByUserNameAsync(string userName, CancellationToken ct = default) 
      => SendAsync<OwnerDto>(
         () => _http.GetAsync($"owners/username/?username={Uri.EscapeDataString(userName)}", ct), ct);

   // GET /owners/name/?name={name}
   public Task<Result<IEnumerable<OwnerDto>>> GetByNameAsync(string name, CancellationToken ct = default) 
      => SendAsync<IEnumerable<OwnerDto>>(
         () => _http.GetAsync($"owners/name/?name={Uri.EscapeDataString(name)}", ct),ct);

   // GET /owners/exists/?username={userName} -> bool body
   public Task<Result<bool>> ExistsByUserNameAsync(string userName, CancellationToken ct = default) 
      => SendAsync<bool>(
         () => _http.GetAsync($"owners/exists/?username={Uri.EscapeDataString(userName)}", ct), ct);
}
