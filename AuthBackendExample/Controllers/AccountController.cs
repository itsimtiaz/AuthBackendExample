using AuthBackend.ViewModels;
using AuthBackendExample.Models;
using AuthBackendExample.Services.AuthServices;
using Microsoft.AspNetCore.Mvc;

namespace AuthBackendExample.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly iAuthServices authServices;

    public AccountController(iAuthServices authServices)
    {
        this.authServices = authServices;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(UserViewModel model)
    {
        var user = new ApplicationUser { Email = model.Email, UserName = model.Email };

        await authServices.Register(user, model.Password, "Admin");

        return Ok();
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(UserViewModel model)
    {
        var user = await authServices.GetUserByEmail(model.Email);

        if (user == null)
        {
            return BadRequest();
        }

        if (await authServices.Login(user, model.Password))
        {
            var jwtToken = await authServices.GetJwtToken(user);
            var refreshToken = await authServices.GetRefreshToken(user);

            Response.Cookies.Append("app_refresh_token", refreshToken, new CookieOptions
            {
                Expires = user.RefreshTokenExpire,
                HttpOnly = true
            });

            return Ok(jwtToken);
        }

        return BadRequest();
    }

    [HttpPost("refresh_token")]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["app_refresh_token"];

        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return Unauthorized();
        }

        var user = await authServices.GetUserByRefreshToken(refreshToken);

        if (user == null)
        {
            return NotFound("User not found!");
        }

        if (user.RefreshTokenExpire <= DateTime.Now)
        {
            await authServices.RevokeUserAccess(user);

            Response.Cookies.Delete("app_refresh_token");

            return Unauthorized();
        }

        var jwtToken = await authServices.GetJwtToken(user);
        
        return Ok(jwtToken);
    }

}
