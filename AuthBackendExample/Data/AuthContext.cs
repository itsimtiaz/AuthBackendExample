using AuthBackendExample.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthBackendExample.Data;

public class AuthContext : IdentityDbContext<ApplicationUser>
{

    public AuthContext(DbContextOptions<AuthContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }

}
