using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Accounts.RyanErskine.Dev.Services
{
    // This class is used by the application to send Email and SMS
    // when you turn on two-factor authentication in ASP.NET Identity.
    // For more details see this link http://go.microsoft.com/fwlink/?LinkID=532713
    public class AuthMessageSender : IEmailSender, ISmsSender
    {
        private readonly ISendGridClient _SendGridClient;

        public AuthMessageSender(ISendGridClient sendGridClient)
        {
            this._SendGridClient = sendGridClient ?? throw new ArgumentNullException(nameof(sendGridClient));
        }

        public async Task SendEmailAsync(string email, string subject, string message, CancellationToken cancellationToken = default)
        {
            var msg = new SendGridMessage()
            {
                From = new EmailAddress(Environment.GetEnvironmentVariable("SendGridFromEmail"), Environment.GetEnvironmentVariable("SendGridFromName")),
                Subject = subject,
                PlainTextContent = message
            };
            msg.AddTo(new EmailAddress(email));
            await this._SendGridClient.SendEmailAsync(msg, cancellationToken);
        }

        public Task SendSmsAsync(string number, string message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }
    }
}
