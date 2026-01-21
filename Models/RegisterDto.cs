using System.ComponentModel.DataAnnotations;

namespace JwtTokenLearn.Models
{
    public class RegisterDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
