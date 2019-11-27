///
///  TODO: Remove this once PR #922 is completed and a new release is available: https://github.com/sendgrid/sendgrid-csharp/pull/922
///

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SendGrid;
using System;
using System.Net.Http;

namespace Accounts.RyanErskine.Dev.Services
{
    public static class Extensions
    {
        public static IHttpClientBuilder AddSendGrid(this IServiceCollection services, Action<IServiceProvider, SendGridClientOptions> configureOptions)
        {
            services.AddOptions<SendGridClientOptions>().Configure<IServiceProvider>((options, resolver) => configureOptions(resolver, options))
                .PostConfigure(options =>
                {
                    if (string.IsNullOrWhiteSpace(options.ApiKey))
                        throw new ArgumentNullException(nameof(options.ApiKey));
                });

            services.TryAddTransient<ISendGridClient>(resolver => resolver.GetRequiredService<InjectableSendGridClient>());
            return services.AddHttpClient<InjectableSendGridClient>();
        }
        public static IHttpClientBuilder AddSendGrid(this IServiceCollection services, Action<SendGridClientOptions> configureOptions)
        {
            return services.AddSendGrid((_, options) => configureOptions(options));
        }
    }

    internal class InjectableSendGridClient : SendGridClient
    {
        public InjectableSendGridClient(HttpClient httpClient, IOptions<SendGridClientOptions> options) : base(httpClient, options.Value) { }
    }
}
