using AuthBackendExample.Models;

namespace AuthBackendExample.Services.AuthServices;

public interface iAuthServices
{
    /// <summary>
    /// Register user
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    Task<ApplicationUser> Register(ApplicationUser user, string password, string role);
    
    /// <summary>
    /// Login user
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    Task<bool> Login(ApplicationUser user, string password);

    /// <summary>
    /// Get JWT token for the user
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    Task<string> GetJwtToken(ApplicationUser user);

    /// <summary>
    /// Get refresh token for the user
    /// </summary>
    /// <returns></returns>
    Task<string> GetRefreshToken(ApplicationUser user);

    /// <summary>
    /// Get user by email
    /// </summary>
    /// <param name="email"></param>
    /// <returns></returns>
    Task<ApplicationUser?> GetUserByEmail(string email);

    /// <summary>
    /// Get user by refresh token
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    Task<ApplicationUser?> GetUserByRefreshToken(string token);

    /// <summary>
    /// Revoke user access by removing refresh token
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    Task<ApplicationUser?> RevokeUserAccess(ApplicationUser user);

}
