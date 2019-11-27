using Microsoft.Extensions.Options;
using SendGrid;
using System.Net.Http;

namespace Accounts.RyanErskine.Dev.Services
{
    internal class InjectableSendGridClient : SendGridClient
    {
        public InjectableSendGridClient(HttpClient httpClient, IOptions<SendGridClientOptions> options)
            : base(httpClient, options.Value)
        {
        }
    }
}
