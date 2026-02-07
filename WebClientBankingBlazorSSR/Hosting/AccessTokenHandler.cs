using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;

namespace WebClientBankingBlazorSSR.Hosting;

public sealed class AccessTokenHandler(IHttpContextAccessor ctx) : DelegatingHandler {
   
   protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
      var httpCtx = ctx.HttpContext;

      if (httpCtx is not null) {
         var token = await httpCtx.GetTokenAsync("access_token");
         if (!string.IsNullOrWhiteSpace(token))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
      }

      return await base.SendAsync(request, ct);
   }
}