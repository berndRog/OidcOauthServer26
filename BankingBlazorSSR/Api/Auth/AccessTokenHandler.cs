using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;

namespace BankingBlazorSsr.Api.Auth;

public sealed class ApiUnauthorizedException : Exception {
   public ApiUnauthorizedException() : base("Unauthorized (access token expired or invalid).") {
   }
}

public sealed class AccessTokenHandler(IHttpContextAccessor ctx) : DelegatingHandler {
   protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
      // Attach bearer token from the current HTTP context (cookie-authenticated UI host)
      var httpCtx = ctx.HttpContext;
      if (httpCtx is not null) {
         var token = await httpCtx.GetTokenAsync("access_token");
         if (!string.IsNullOrWhiteSpace(token))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
      }

      var response = await base.SendAsync(request, ct);

      // Central detection: token expired/invalid -> let UI redirect to login
      if (response.StatusCode == HttpStatusCode.Unauthorized)
         throw new ApiUnauthorizedException();

      return response;
   }
}