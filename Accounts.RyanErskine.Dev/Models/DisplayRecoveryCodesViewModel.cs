using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Accounts.RyanErskine.Dev.Models
{
    public class DisplayRecoveryCodesViewModel
    {
        [Required]
        public IEnumerable<string> Codes { get; set; }

    }
}
