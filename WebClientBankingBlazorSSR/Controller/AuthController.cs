using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebClientBankingBlazorSSR.Controllers;

[AllowAnonymous]
public sealed class AuthController : Controller {
   
   [HttpGet("/login")]
   public IActionResult Login([FromQuery] string? returnUrl = "/") {
      var props = new AuthenticationProperties {
         RedirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl
      };

      return Challenge(props, OpenIdConnectDefaults.AuthenticationScheme);
   }

   [HttpGet("/logout")]
   public IActionResult Logout() {
      var props = new AuthenticationProperties { RedirectUri = "/" };

      return SignOut(
         props,
         OpenIdConnectDefaults.AuthenticationScheme,
         CookieAuthenticationDefaults.AuthenticationScheme
      );
   }
}