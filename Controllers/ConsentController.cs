using IdentityServer4.Events;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;
using Accounts.RyanErskine.Dev.Security;
using System;
using Accounts.RyanErskine.Dev.Models;

namespace Accounts.RyanErskine.Dev.Controllers
{
    /// <summary>
    /// This controller processes the consent UI
    /// </summary>
    [SecurityHeaders]
    [Authorize]
    public class ConsentController : Controller
    {
        private readonly IIdentityServerInteractionService _Interaction;
        private readonly IClientStore _ClientStore;
        private readonly IResourceStore _ResourceStore;
        private readonly IEventService _Events;
        private readonly ILogger<ConsentController> _Logger;

        public ConsentController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IResourceStore resourceStore,
            IEventService events,
            ILogger<ConsentController> logger)
        {
            this._Interaction = interaction ?? throw new ArgumentNullException(nameof(interaction));
            this._ClientStore = clientStore ?? throw new ArgumentNullException(nameof(clientStore));
            this._ResourceStore = resourceStore ?? throw new ArgumentNullException(nameof(resourceStore));
            this._Events = events ?? throw new ArgumentNullException(nameof(events));
            this._Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Shows the consent screen
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> Index(string returnUrl)
        {
            var vm = await this.BuildViewModelAsync(returnUrl);
            if (vm != null)
                return View("Index", vm);

            return View("Error");
        }

        /// <summary>
        /// Handles the consent screen postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(ConsentInputModel model)
        {
            var result = await this.ProcessConsent(model);

            if (result.IsRedirect)
            {
                if (await this._ClientStore.IsPkceClientAsync(result.ClientId))
                    // if the client is PKCE then we assume it's native, so this change in how to
                    // return the response is for better UX for the end user.
                    return View("Redirect", new RedirectViewModel { RedirectUrl = result.RedirectUri });

                return Redirect(result.RedirectUri);
            }

            if (result.HasValidationError)
                ModelState.AddModelError(string.Empty, result.ValidationError);

            if (result.ShowView)
                return View("Index", result.ViewModel);

            return View("Error");
        }

        /*****************************************/
        /* helper APIs for the ConsentController */
        /*****************************************/
        private async Task<ProcessConsentResult> ProcessConsent(ConsentInputModel model)
        {
            var result = new ProcessConsentResult();

            // validate return url is still valid
            var request = await this._Interaction.GetAuthorizationContextAsync(model.ReturnUrl);
            if (request == null) return result;

            ConsentResponse grantedConsent = null;

            // user clicked 'no' - send back the standard 'access_denied' response
            if (model?.Button == "no")
            {
                grantedConsent = ConsentResponse.Denied;
                await this._Events.RaiseAsync(new ConsentDeniedEvent(User.GetSubjectId(), request.ClientId, request.ScopesRequested));
            }
            // user clicked 'yes' - validate the data
            else if (model?.Button == "yes")
            {
                // if the user consented to some scope, build the response model
                if (model.ScopesConsented != null && model.ScopesConsented.Any())
                {
                    var scopes = model.ScopesConsented;
                    if (ConsentOptions.EnableOfflineAccess == false)
                        scopes = scopes.Where(x => x != IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess);

                    grantedConsent = new ConsentResponse
                    {
                        RememberConsent = model.RememberConsent,
                        ScopesConsented = scopes.ToArray()
                    };

                    // emit event
                    await this._Events.RaiseAsync(new ConsentGrantedEvent(User.GetSubjectId(), request.ClientId, request.ScopesRequested, grantedConsent.ScopesConsented, grantedConsent.RememberConsent));
                }
                else
                {
                    result.ValidationError = ConsentOptions.MustChooseOneErrorMessage;
                }
            }
            else
            {
                result.ValidationError = ConsentOptions.InvalidSelectionErrorMessage;
            }

            if (grantedConsent != null)
            {
                // communicate outcome of consent back to identityserver
                await this._Interaction.GrantConsentAsync(request, grantedConsent);

                // indicate that's it ok to redirect back to authorization endpoint
                result.RedirectUri = model.ReturnUrl;
                result.ClientId = request.ClientId;
            }
            else
            {
                // we need to redisplay the consent UI
                result.ViewModel = await this.BuildViewModelAsync(model.ReturnUrl, model);
            }

            return result;
        }

        private async Task<ConsentViewModel> BuildViewModelAsync(string returnUrl, ConsentInputModel model = null)
        {
            var request = await this._Interaction.GetAuthorizationContextAsync(returnUrl);
            if (request == null)
            {
                this._Logger.LogError("No consent request matching request: {0}", returnUrl);
                return null;
            }

            var client = await this._ClientStore.FindEnabledClientByIdAsync(request.ClientId);
            if (client == null)
            {
                this._Logger.LogError("Invalid client id: {0}", request.ClientId);
                return null;
            }

            var resources = await this._ResourceStore.FindEnabledResourcesByScopeAsync(request.ScopesRequested);
            if (resources != null && (resources.IdentityResources.Any() || resources.ApiResources.Any()))
                return this.CreateConsentViewModel(model, returnUrl, request, client, resources);
            else
                this._Logger.LogError("No scopes matching: {0}", request.ScopesRequested.Aggregate((x, y) => x + ", " + y));

            return null;
        }

        private ConsentViewModel CreateConsentViewModel(ConsentInputModel model, string returnUrl, AuthorizationRequest request, Client client, Resources resources)
        {
            var vm = new ConsentViewModel
            {
                RememberConsent = model?.RememberConsent ?? true,
                ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>(),

                ReturnUrl = returnUrl,

                ClientName = client.ClientName ?? client.ClientId,
                ClientUrl = client.ClientUri,
                ClientLogoUrl = client.LogoUri,
                AllowRememberConsent = client.AllowRememberConsent
            };

            vm.IdentityScopes = resources.IdentityResources.Select(x => this.CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
            vm.ResourceScopes = resources.ApiResources.SelectMany(x => x.Scopes).Select(x => this.CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
            if (ConsentOptions.EnableOfflineAccess && resources.OfflineAccess)
                vm.ResourceScopes = vm.ResourceScopes.Union(new ScopeViewModel[] {
                    this.GetOfflineAccessScope(vm.ScopesConsented.Contains(IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess) || model == null)
                });

            return vm;
        }

        private ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check)
            => new ScopeViewModel
                {
                    Name = identity.Name,
                    DisplayName = identity.DisplayName,
                    Description = identity.Description,
                    Emphasize = identity.Emphasize,
                    Required = identity.Required,
                    Checked = check || identity.Required
                };

        public ScopeViewModel CreateScopeViewModel(Scope scope, bool check)
            => new ScopeViewModel
                {
                    Name = scope.Name,
                    DisplayName = scope.DisplayName,
                    Description = scope.Description,
                    Emphasize = scope.Emphasize,
                    Required = scope.Required,
                    Checked = check || scope.Required
                };

        private ScopeViewModel GetOfflineAccessScope(bool check)
            => new ScopeViewModel
                {
                    Name = IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess,
                    DisplayName = ConsentOptions.OfflineAccessDisplayName,
                    Description = ConsentOptions.OfflineAccessDescription,
                    Emphasize = true,
                    Checked = check
                };
    }
}
