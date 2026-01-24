using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using WebClientMvc.Models.ViewModels;
using WebClientMvc.Services;

namespace WebClientMvc.Controllers;

public sealed class HomeController(
   CustomersApiClient _customersApi   // dein API-Client
) : Controller {

   [HttpGet]
   public async Task<IActionResult> Index(CancellationToken ct) {

      // 1) Anonym -> Startseite wie bisher
      if (User.Identity?.IsAuthenticated != true)
         return View();

      // 2) Access Token aus OIDC Session holen
      var accessToken = await HttpContext.GetTokenAsync("access_token");
      if (string.IsNullOrWhiteSpace(accessToken))
         return Challenge(); // Session kaputt -> neu einloggen

      // 3) Customer provisioning (idempotent, jedes Login ok)
      var resultProvisioned = await _customersApi.EnsureProvisionedAsync(accessToken, ct);
      if (!resultProvisioned.IsSuccess)
      if (!resultProvisioned.IsSuccess) {
         ViewBag.ErrorTitle = resultProvisioned.Problem?.Title ?? "Provisioning failed";
         ViewBag.ErrorDetail = resultProvisioned.Problem?.Detail;
         return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier });
      }
      
      // 4) Profil laden
      var resultProfile = await _customersApi.GetMyProfileAsync(accessToken, ct);
      if (!resultProfile.IsSuccess) {
         ViewBag.ErrorTitle = resultProfile.Problem?.Title ?? "Loading customer profile failed";
         ViewBag.ErrorDetail = resultProfile.Problem?.Detail;
         return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier });
      }

      // 5) Profil unvollständig? -> Eingabedialog
      if (string.IsNullOrWhiteSpace(resultProfile.Value!.FirstName) ||
          string.IsNullOrWhiteSpace(resultProfile.Value!.LastName))
         return RedirectToAction("Edit", "Profile");

      // 6) Alles ok -> normale Startseite (Profil optional anzeigen)
      return View(resultProfile.Value);
   }

}
