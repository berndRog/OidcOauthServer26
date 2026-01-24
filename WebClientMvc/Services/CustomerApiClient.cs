using System.Net.Http.Headers;
using WebClientMvc.Models.Dtos;
namespace WebClientMvc.Services;

public sealed class CustomersApiClient(
   HttpClient _httpCient
) {

   // POST customers/provisioned  -> Guid (customerId)
   public async Task<ApiResult<Guid>> EnsureProvisionedAsync(
      string accessToken,
      CancellationToken ct
   ) {
      using var request = new HttpRequestMessage(HttpMethod.Post, "customers/provisioned");
      request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

      using var response = await _httpCient.SendAsync(request, ct);
      if (response.IsSuccessStatusCode) {
         var id = await response.Content.ReadFromJsonAsync<Guid>(cancellationToken: ct);
         return ApiResult<Guid>.Ok(id);
      }

      return await ApiResult<Guid>.FromErrorResponseAsync(response, ct);
   }

   // GET customers/profile -> CustomerProfileDto (404 if not provisioned)
   public async Task<ApiResult<CustomerProfileDto>> GetMyProfileAsync(
      string accessToken,
      CancellationToken ct
   ) {
      using var request = new HttpRequestMessage(HttpMethod.Get, "customers/profile");
      request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

      using var response = await _httpCient.SendAsync(request, ct);
      if (response.IsSuccessStatusCode) {
         var dto = await response.Content.ReadFromJsonAsync<CustomerProfileDto>(cancellationToken: ct);
         return ApiResult<CustomerProfileDto>.Ok(dto!);
      }

      return await ApiResult<CustomerProfileDto>.FromErrorResponseAsync(response, ct);
   }

   // PUT /api/customers/profile -> CustomerProfileDto
   public async Task<ApiResult<CustomerProfileDto>> UpdateMyProfileAsync(
      string accessToken,
      CustomerProfileDto dto,
      CancellationToken ct
   ) {
      using var request = new HttpRequestMessage(HttpMethod.Put, "customers/profile");
      request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
      request.Content = JsonContent.Create(dto);

      using var response = await _httpCient.SendAsync(request, ct);
      if (response.IsSuccessStatusCode) {
         var updated = await response.Content.ReadFromJsonAsync<CustomerProfileDto>(cancellationToken: ct);
         return ApiResult<CustomerProfileDto>.Ok(updated!);
      }

      return await ApiResult<CustomerProfileDto>.FromErrorResponseAsync(response, ct);
   }
}