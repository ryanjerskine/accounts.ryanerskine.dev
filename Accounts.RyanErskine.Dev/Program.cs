using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace Accounts.RyanErskine.Dev
{
    public class Program
    {
        public static void Main(string[] args)
        {
#if DEBUG
            DotNetEnv.Env.Load();
#endif
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
