using System.ComponentModel.DataAnnotations;

namespace Accounts.RyanErskine.Dev.Models
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
