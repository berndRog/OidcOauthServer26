using System.Net.Http.Headers;
using BankingBlazorSsr.Api.Errors;
using BankingBlazorSsr.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace BankingBlazorSsr.Api.Auth;

public sealed class AccessTokenHandler(
   IHttpContextAccessor ctxAccessor,
   IHttpClientFactory httpClientFactory,
   IConfiguration config,
   ILogger<AccessTokenHandler> logger
) : DelegatingHandler {
   protected override async Task<HttpResponseMessage> SendAsync(
      HttpRequestMessage request, 
      CancellationToken ct
   ) {
      var httpCtx = ctxAccessor.HttpContext;

      if (httpCtx is not null) {
         try {
            _ = await httpCtx.TryRefreshAccessTokenAsync(httpClientFactory, config, ct);
         }
         catch (Exception ex) {
            logger.LogWarning(ex, "Silent token refresh failed.");
         }
         var token = await httpCtx.GetTokenAsync("access_token");
         if (!string.IsNullOrWhiteSpace(token))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
      }

      var response = await base.SendAsync(request, ct);

      if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
         throw new ApiUnauthorizedException();

      return response;
   }
}

public sealed class ApiUnauthorizedException : Exception {
   public ApiUnauthorizedException() : 
      base("Unauthorized (access token expired or invalid).") { }
}