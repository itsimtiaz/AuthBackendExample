using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthBackendExample.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class UserController : ControllerBase
{
    [HttpGet]
    public IActionResult GetUserDetails()
    {
        var claims = User.Claims;

        var email = claims.SingleOrDefault(x => x.Type == ClaimTypes.Email);

        return Ok(email?.Value);
    }
}
