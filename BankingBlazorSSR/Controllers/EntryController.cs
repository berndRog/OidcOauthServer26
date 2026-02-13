using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using BankingBlazorSsr.Api.Clients;

namespace BankingBlazorSsr.Controllers;

[Authorize]
public sealed class EntryController(
   ILogger<EntryController> logger
) : Controller {
   [HttpGet("/entry")]
   public IActionResult Index() {
      if (User.IsInRole("Owner"))
         return Redirect("/owners/provision");

      if (User.IsInRole("Employee"))
         return Redirect("/employee/provision");

      logger.LogWarning("Entry: user has no supported role.");
      return Redirect("/no-access");
   }
}