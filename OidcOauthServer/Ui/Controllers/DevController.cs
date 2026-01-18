using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace OidcOauthServer.Ui.Controllers;

[ApiController]
[Route("dev")]
public sealed class DevController : ControllerBase
{
   [HttpGet("ping")]
   [Authorize] // token must be valid
   public IActionResult Ping() => Ok(new {
      ok = true,
      authType = User.Identity?.AuthenticationType,
      claims = User.Claims.Select(c => new { c.Type, c.Value })
   });
}
