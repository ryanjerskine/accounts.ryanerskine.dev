using System.Threading.Tasks;

namespace Accounts.RyanErskine.Dev.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }
}
