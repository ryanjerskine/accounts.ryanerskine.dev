using Accounts.RyanErskine.Dev.Models;
using Accounts.RyanErskine.Dev.Security;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace Accounts.RyanErskine.Dev.Controllers
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IIdentityServerInteractionService _Interaction;
        private readonly IWebHostEnvironment _Environment;
        private readonly ILogger _Logger;

        public HomeController(IIdentityServerInteractionService interaction, IWebHostEnvironment environment, ILogger<HomeController> logger)
        {
            this._Interaction = interaction ?? throw new ArgumentNullException(nameof(interaction));
            this._Environment = environment ?? throw new ArgumentNullException(nameof(environment));
            this._Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // GET: /home
        public IActionResult Index()
        {
            if (this._Environment.IsDevelopment())
                // only show in development
                return View();

            this._Logger.LogInformation("Homepage is disabled in production. Returning 404.");
            return NotFound();
        }

        // GET: /home/error
        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

            // retrieve error details from identityserver
            var message = await this._Interaction.GetErrorContextAsync(errorId);

            if (message == null)
                return View("error", vm);

            vm.Error = message;
            if (!this._Environment.IsDevelopment())
                // only show in development
                message.ErrorDescription = null;

            return View("error", vm);
        }
    }
}
