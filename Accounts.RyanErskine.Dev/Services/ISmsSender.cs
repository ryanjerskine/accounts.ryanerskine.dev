using System.Threading.Tasks;

namespace Accounts.RyanErskine.Dev.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
