using System;
using System.Diagnostics;
using Accounts.RyanErskine.Dev.Data;
using Accounts.RyanErskine.Dev.Models;
using Accounts.RyanErskine.Dev.Services;
using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SendGrid;

namespace Accounts.RyanErskine.Dev
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services.AddRouting(options =>
            {
                options.LowercaseUrls = true;
            });

            // Asp Identity
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Environment.GetEnvironmentVariable("SqlConnectionString")));
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // IdentityServer
            var builder = services.AddIdentityServer()
                .AddInMemoryCaching()
                .AddAspNetIdentity<ApplicationUser>()
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = b => b.UseSqlServer(Environment.GetEnvironmentVariable("SqlConnectionString"), sql => sql.MigrationsAssembly(null));
                })
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = b => b.UseSqlServer(Environment.GetEnvironmentVariable("SqlConnectionString"), sql => sql.MigrationsAssembly(null));
                    // TODO: Decide what defaults should be for token cleanup
                    options.EnableTokenCleanup = true;
                    options.TokenCleanupInterval = 30;
                });

            // Signing Credentials
            if (Debugger.IsAttached)
                builder.AddDeveloperSigningCredential();
            else
                throw new Exception("Proper signing credentials should be configured prior to deploying");

            // Email and SMS
            services.AddSendGrid(options =>
            {
                options.ApiKey = Environment.GetEnvironmentVariable("SendGridApiKey");
            });
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();

            // Auth and Optional Integrations
            var authBuilder = services.AddAuthentication();
            var useGoogle = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("GoogleClientId"));
            if (useGoogle)
                authBuilder.AddGoogle("Google", options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.ClientId = Environment.GetEnvironmentVariable("GoogleClientId");
                    options.ClientSecret = Environment.GetEnvironmentVariable("GoogleClientSecret");
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
