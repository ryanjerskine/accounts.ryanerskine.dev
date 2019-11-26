using System.ComponentModel.DataAnnotations;

namespace Accounts.RyanErskine.Dev.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
