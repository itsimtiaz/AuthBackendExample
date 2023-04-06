using AuthBackendExample.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthBackendExample.Services.AuthServices;

public class AuthServices : iAuthServices
{
    private readonly UserManager<ApplicationUser> userManager;
    private readonly RoleManager<IdentityRole> roleManager;
    private readonly SignInManager<ApplicationUser> signInManager;
    private readonly IConfiguration configuration;

    public AuthServices(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
        SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
    {
        this.userManager = userManager;
        this.roleManager = roleManager;
        this.signInManager = signInManager;
        this.configuration = configuration;
    }
    public async Task<string> GetJwtToken(ApplicationUser user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetSection("JWT").GetValue<string>("secret")));
        var signingKey = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var roles = await userManager.GetRolesAsync(user);
        var claims = new List<Claim>();

        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
        claims.Add(new Claim(ClaimTypes.Email, user.Email));

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        var token = new JwtSecurityToken(issuer: configuration.GetSection("JWT").GetValue<string>("issuer"),
            audience: configuration.GetSection("JWT").GetValue<string>("audience"),
            claims: claims, notBefore: DateTime.Now, expires: DateTime.Now.AddSeconds(20), signingCredentials: signingKey);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<string> GetRefreshToken(ApplicationUser user)
    {
        var bytes = new byte[64];
        var randomGenerator = RandomNumberGenerator.Create();
        randomGenerator.GetBytes(bytes);

        var refreshToken = Convert.ToBase64String(bytes);

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpire = DateTime.Now.AddMinutes(5);

        await userManager.UpdateAsync(user);

        return refreshToken;
    }

    public async Task<ApplicationUser?> GetUserByEmail(string email)
    {
        return await userManager.FindByEmailAsync(email);
    }

    public async Task<ApplicationUser?> GetUserByRefreshToken(string token)
    {
        return await userManager.Users.SingleOrDefaultAsync(e => e.RefreshToken == token);
    }

    public async Task<bool> Login(ApplicationUser user, string password)
    {
        var loginResult = await signInManager.CheckPasswordSignInAsync(user, password, false);
        return loginResult.Succeeded;
    }

    public async Task<ApplicationUser> Register(ApplicationUser user, string password, string role)
    {
        await userManager.CreateAsync(user, password);

        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }

        await userManager.AddToRoleAsync(user, role);

        return user;
    }

    public async Task<ApplicationUser?> RevokeUserAccess(ApplicationUser user)
    {
        user.RefreshToken = null;
        user.RefreshTokenExpire = null;

        await userManager.UpdateAsync(user);
        return user;
    }
}
