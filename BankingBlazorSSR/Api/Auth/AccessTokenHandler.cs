using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace BankingBlazorSsr.Api.Auth;

public sealed class AccessTokenHandler(
   IHttpContextAccessor ctxAccessor,
   IHttpClientFactory httpClientFactory,
   IConfiguration config
) : DelegatingHandler
{
   protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
   {
      var httpCtx = ctxAccessor.HttpContext;

      if (httpCtx is not null)
      {
         // Try refresh silently if needed
         await httpCtx.TryRefreshAccessTokenAsync(httpClientFactory, config, ct);

         var token = await httpCtx.GetTokenAsync("access_token");
         if (!string.IsNullOrWhiteSpace(token))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
      }

      return await base.SendAsync(request, ct);
   }
}
public sealed class ApiUnauthorizedException : Exception {
   public ApiUnauthorizedException() : base("Unauthorized (access token expired or invalid).") {
   }
}
