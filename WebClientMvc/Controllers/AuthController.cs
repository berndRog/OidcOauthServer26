using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebClientMvc.Models;

namespace WebClientMvc.Controllers;

public sealed class AuthController : Controller {
   [HttpGet("~/login")]
   public IActionResult Login(string returnUrl = "/me") =>
      Challenge(
         new AuthenticationProperties { RedirectUri = returnUrl },
         OpenIdConnectDefaults.AuthenticationScheme
      );

   [Authorize]
   [HttpGet("~/logout")]
   public IActionResult Logout() =>
      SignOut(
         new AuthenticationProperties { RedirectUri = "/" },
         OpenIdConnectDefaults.AuthenticationScheme,
         CookieAuthenticationDefaults.AuthenticationScheme
      );

   [Authorize]
   [HttpGet("~/me")]
   public async Task<IActionResult> Me() {
      var vm = new MeViewModel {
         UserName = User.Identity?.Name,
         IdToken = await HttpContext.GetTokenAsync("id_token"),
         AccessToken = await HttpContext.GetTokenAsync("access_token"),
         RefreshToken = await HttpContext.GetTokenAsync("refresh_token"),
         ExpiresAt = await HttpContext.GetTokenAsync("expires_at"),
         Claims = User.Claims
            .Select(c => new ClaimItem(c.Type, c.Value))
            .OrderBy(c => c.Type)
            .ToList()
      };

      return View(vm); // => Views/Auth/Me.cshtml
   }
}