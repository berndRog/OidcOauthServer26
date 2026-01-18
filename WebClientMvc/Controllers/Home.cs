using Microsoft.AspNetCore.Mvc;

namespace WebClientMvc.Controllers;

public sealed class HomeController : Controller
{
   [HttpGet]
   public IActionResult Index() => View();
}