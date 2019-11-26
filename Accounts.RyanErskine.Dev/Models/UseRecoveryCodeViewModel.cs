using System.ComponentModel.DataAnnotations;

namespace Accounts.RyanErskine.Dev.Models
{
    public class UseRecoveryCodeViewModel
    {
        [Required]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }
    }
}
