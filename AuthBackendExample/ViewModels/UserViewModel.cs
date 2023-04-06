using System.ComponentModel.DataAnnotations;

namespace AuthBackend.ViewModels;

public class UserViewModel
{
    [DataType(DataType.EmailAddress)]
    [Required]
    public string Email { get; set; } = string.Empty;
    
    [Required, MinLength(3)]
    public string Password { get; set; } = string.Empty;

}
