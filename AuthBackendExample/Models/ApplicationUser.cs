using Microsoft.AspNetCore.Identity;

namespace AuthBackendExample.Models;

public class ApplicationUser : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpire { get; set; }
}
