using System.Net;
using Microsoft.AspNetCore.Mvc;
namespace WebClientMvc.Services;

/// <summary>
/// Small wrapper to unify successful results and error responses
/// (ProblemDetails + HTTP status).
/// </summary>
public sealed class ApiResult<T> {
   public bool IsSuccess { get; }
   public T? Value { get; }
   public int StatusCode { get; }
   public ProblemDetails? Problem { get; }

   private ApiResult(bool ok, T? value, int statusCode, ProblemDetails? problem) {
      IsSuccess = ok;
      Value = value;
      StatusCode = statusCode;
      Problem = problem;
   }

   public static ApiResult<T> Ok(T value) =>
      new(true, value, (int)HttpStatusCode.OK, null);

   public static async Task<ApiResult<T>> FromErrorResponseAsync(HttpResponseMessage res, CancellationToken ct) {
      ProblemDetails? pd = null;

      // Try read ProblemDetails (application/problem+json)
      try {
         pd = await res.Content.ReadFromJsonAsync<ProblemDetails>(cancellationToken: ct);
      }
      catch {
         // ignore parsing errors; we still return status code
      }

      pd ??= new ProblemDetails {
         Title = "API request failed",
         Detail = await SafeReadStringAsync(res, ct),
         Status = (int)res.StatusCode
      };

      return new(false, default, (int)res.StatusCode, pd);
   }

   private static async Task<string?> SafeReadStringAsync(HttpResponseMessage res, CancellationToken ct) {
      try { return await res.Content.ReadAsStringAsync(ct); }
      catch { return null; }
   }
}
