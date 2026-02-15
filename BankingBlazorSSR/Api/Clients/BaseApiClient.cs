using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using BankingBlazorSsr.Api.Auth;
using BankingBlazorSsr.Api.Errors;
using BankingBlazorSsr.Core;
using Microsoft.AspNetCore.Mvc;
namespace BankingBlazorSsr.Api.Clients;

public abstract class BaseApiClient<TClient>(
   IHttpClientFactory factory,
   JsonSerializerOptions json,
   ILogger<TClient> logger
) where TClient : class {

   // to have access in derived clients without passing around in each method;
   // also allows derived clients to use _http for custom calls if needed.
   protected readonly HttpClient _http = factory.CreateClient("BankingApi");
   protected readonly JsonSerializerOptions _json = json;
   protected readonly ILogger<TClient> _logger = logger;
   
   protected async Task<Result<T>> SendAsync<T>(
      Func<Task<HttpResponseMessage>> send,
      CancellationToken ct = default
   ) {
      HttpResponseMessage response;

      try {
         response = await send();
      }
      catch (ApiUnauthorizedException) {
         // Token expired/invalid (detected centrally in AccessTokenHandler)
         return Result<T>.Failure(new ApiError(
            Status: 401,
            Title: "Unauthorized",
            Detail: "Session expired. Please login again."
         ));
      }
      catch (OperationCanceledException ex) {
         _logger.LogWarning(ex, "Request canceled.");
         return Result<T>.Failure(new ApiError(0, "Request canceled", ex.Message));
      }
      catch (Exception ex) {
         _logger.LogError(ex, "Network error.");
         return Result<T>.Failure(new ApiError(0, "Network error", ex.Message));
      }

      // 204 NoContent -> for bool treat as success(true)
      if (response.StatusCode == HttpStatusCode.NoContent) {
         if (typeof(T) == typeof(bool))
            return Result<T>.Success((T)(object)true);

         return Result<T>.Success(default!);
      }

      if (response.IsSuccessStatusCode) {
         // Strict bool handling:
         // - If body is truly empty => true
         // - Else must be valid JSON bool
         if (typeof(T) == typeof(bool)) {
            
            // Guard against null content (e.g. some APIs might return 204 with no body, or Content-Length: 0)
            var content = response.Content;
            if (content is null)
               return Result<T>.Success((T)(object)true);
            
            // Fast path: declared empty
            if (response.Content.Headers?.ContentLength == 0)
               return Result<T>.Success((T)(object)true);

            // If no content-type is set, it's often an empty body; verify cheaply.
            MediaTypeHeaderValue? ctHeader = response.Content.Headers?.ContentType;

            if (ctHeader is null) {
               var raw = await response.Content.ReadAsStringAsync(ct);
               if (string.IsNullOrWhiteSpace(raw))
                  return Result<T>.Success((T)(object)true);

               // content exists but isn't a JSON bool -> treat as invalid payload
               return Result<T>.Failure(new ApiError(
                  Status: (int)response.StatusCode,
                  Title: "Invalid response payload",
                  Detail: $"Expected JSON boolean but got: {raw}"
               ));
            }

            // Content-Type exists: require JSON bool
            try {
               var b = await response.Content.ReadFromJsonAsync<bool>(_json, ct);
               return Result<T>.Success((T)(object)b);
            }
            catch (Exception ex) {
               _logger.LogError(ex, "Failed to parse bool response.");
               return Result<T>.Failure(new ApiError(
                  Status: (int)response.StatusCode,
                  Title: "Invalid response payload",
                  Detail: ex.Message
               ));
            }
         }

         // Normal success: deserialize JSON into T
         try {
            var data = await response.Content.ReadFromJsonAsync<T>(_json, ct);
            return Result<T>.Success(data!);
         }
         catch (Exception ex) {
            _logger.LogError(ex, "Invalid success payload.");
            return Result<T>.Failure(new ApiError(
               Status: (int)response.StatusCode,
               Title: "Invalid response payload",
               Detail: ex.Message
            ));
         }
      }

      var apiError = await ToApiError(response, ct);

      _logger.LogWarning(
         "API error {Status}: {Title} - {Detail}",
         apiError.Status,
         apiError.Title,
         apiError.Detail
      );

      return Result<T>.Failure(apiError);
   }

   private async Task<ApiError> ToApiError(
      HttpResponseMessage response,
      CancellationToken ct
   ) {
      // Your API returns ProblemDetails with Title/Detail/Status.
      try {
         var pd = await response.Content.ReadFromJsonAsync<ProblemDetails>(_json, ct);

         var errorCode =
            pd?.Extensions is not null &&
            pd.Extensions.TryGetValue("errorCode", out var codeObj)
               ? codeObj?.ToString()
               : null;

         return new ApiError(
            Status: (int)response.StatusCode,
            Title: pd?.Title ?? $"HTTP {(int)response.StatusCode}",
            Detail: pd?.Detail,
            ErrorCode: errorCode
         );
      }
      catch {
         // Fallback: raw response
         string? raw;
         try {
            raw = await response.Content.ReadAsStringAsync(ct);
         }
         catch {
            raw = null;
         }

         return new ApiError(
            Status: (int)response.StatusCode,
            Title: $"HTTP {(int)response.StatusCode}",
            Detail: raw
         );
      }
   }
}