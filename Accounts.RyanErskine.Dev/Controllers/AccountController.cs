using Accounts.RyanErskine.Dev.Models;
using Accounts.RyanErskine.Dev.Security;
using Accounts.RyanErskine.Dev.Services;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Accounts.RyanErskine.Dev.Controllers
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [SecurityHeaders]
    [Authorize]
    [Route("account")]
    public class AccountController : Controller
    {
        private readonly ILogger _Logger;
        private readonly UserManager<ApplicationUser> _UserManager;
        private readonly SignInManager<ApplicationUser> _SignInManager;
        private readonly IIdentityServerInteractionService _Interaction;
        private readonly IClientStore _ClientStore;
        private readonly IAuthenticationSchemeProvider _SchemeProvider;
        private readonly IEventService _Events;
        private readonly IEmailSender _EmailSender;
        private readonly ISmsSender _SmsSender;

        public AccountController(
            ILogger<AccountController> logger,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IEmailSender emailSender,
            ISmsSender smsSender)
        {
            this._Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this._UserManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            this._SignInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
            this._Interaction = interaction ?? throw new ArgumentNullException(nameof(interaction));
            this._ClientStore = clientStore ?? throw new ArgumentNullException(nameof(clientStore));
            this._SchemeProvider = schemeProvider ?? throw new ArgumentNullException(nameof(schemeProvider));
            this._Events = events ?? throw new ArgumentNullException(nameof(events));
            this._EmailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
            this._SmsSender = smsSender ?? throw new ArgumentNullException(nameof(smsSender));
        }

        // GET: /account/login
        [HttpGet("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string ReturnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await this.BuildLoginViewModelAsync(ReturnUrl);

            if (vm.IsExternalLoginOnly)
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("challenge", "external", new { provider = vm.ExternalLoginScheme, ReturnUrl });

            return View(vm);
        }

        // POST: /account/login
        [HttpPost("login")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await this._Interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context == null) return Redirect("~/");

                // if the user cancels, send a result back into IdentityServer as if they 
                // denied the consent (even if this client does not require consent).
                // this will send back an access denied OIDC error response to the client.
                await this._Interaction.GrantConsentAsync(context, ConsentResponse.Denied);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                if (await this._ClientStore.IsPkceClientAsync(context.ClientId))
                    // if the client is PKCE then we assume it's native, so this change in how to
                    // return the response is for better UX for the end user.
                    return View("redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });

                return Redirect(model.ReturnUrl);
            }

            if (ModelState.IsValid)
            {
                var result = await this._SignInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = await this._UserManager.FindByNameAsync(model.Username);
                    await this._Events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

                    if (context != null)
                    {
                        if (await this._ClientStore.IsPkceClientAsync(context.ClientId))
                            // if the client is PKCE then we assume it's native, so this change in how to
                            // return the response is for better UX for the end user.
                            return View("redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                        return Redirect(model.ReturnUrl);
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                        return Redirect("~/");
                    else
                        throw new Exception("invalid return URL"); // user might have clicked on a malicious link - should be logged
                }

                await this._Events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await this.BuildLoginViewModelAsync(model);
            return View(vm);
        }

        // GET: /account/register
        [HttpGet("register")]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["returnUrl"] = returnUrl;
            return View();
        }

        // POST: /account/register
        [HttpPost("register")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            ViewData["returnUrl"] = returnUrl;

            if (!ModelState.IsValid)
                return View(model);

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await this._UserManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                this.AddErrors(result);
                return View(model);
            }

            // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
            // Send an email with this link
            var code = await this._UserManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Action("confirm-email", "account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
            await this._EmailSender.SendEmailAsync(model.Email, Resources.EmailMessages.ConfirmAccountSubject, string.Format(Resources.EmailMessages.ConfirmAccountMessage, callbackUrl));
            await this._SignInManager.SignInAsync(user, isPersistent: false);
            this. _Logger.LogInformation(3, "User created a new account with password.");
            return this.RedirectToLocal(returnUrl);
        }

        // GET: /account/logout
        [HttpGet("logout")]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await this.BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await this.Logout(vm);

            return View(vm);
        }

        // POST: /account/logout
        [HttpPost("logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await this.BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await this._SignInManager.SignOutAsync();
                // raise the logout event
                await this._Events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("logout", new { logoutId = vm.LogoutId });
                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        // GET: account/access-denied
        [HttpGet("access-denied")]
        public IActionResult AccessDenied()
            => View();

        // POST: /account/external-login
        [HttpPost("external-login")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { returnUrl = returnUrl });
            var properties = this._SignInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        // GET: /account/external-login-callback
        [HttpGet("external-login-callback")]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View("login");
            }

            var info = await this._SignInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return RedirectToAction("login");

            // Sign in the user with this external login provider if the user already has a login.
            var result = await this._SignInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
            {
                // Update any authentication tokens if login succeeded
                await this._SignInManager.UpdateExternalAuthenticationTokensAsync(info);
                this._Logger.LogInformation(5, "User logged in with {Name} provider.", info.LoginProvider);
                return RedirectToLocal(returnUrl);
            }

            if (result.RequiresTwoFactor)
                return RedirectToAction("send-code", new { returnUrl = returnUrl });

            if (result.IsLockedOut)
                return View("lockout");

            // If the user does not have an account, then ask the user to create an account.
            ViewData["returnUrl"] = returnUrl;
            ViewData["providerDisplayName"] = info.ProviderDisplayName;
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            return View("external-login-confirmation", new ExternalLoginConfirmationViewModel { Email = email });
        }

        // POST: /account/external-login-confirmation
        [HttpPost("external-login-confirmation")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                ViewData["returnUrl"] = returnUrl;
                return View(model);
            }

            // Get the information about the user from the external login provider
            var info = await this._SignInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return View("external-login-failure");
            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await this._UserManager.CreateAsync(user);

            if (!result.Succeeded)
            {
                this.AddErrors(result);
                ViewData["returnUrl"] = returnUrl;
                return View(model);
            }

            result = await this._UserManager.AddLoginAsync(user, info);
            if (!result.Succeeded)
            {
                this.AddErrors(result);
                ViewData["returnUrl"] = returnUrl;
                return View(model);
            }

            await this._SignInManager.SignInAsync(user, isPersistent: false);
            this._Logger.LogInformation(6, "User created an account using {Name} provider.", info.LoginProvider);
            // Update any authentication tokens as well
            await this._SignInManager.UpdateExternalAuthenticationTokensAsync(info);
            return RedirectToLocal(returnUrl);
        }

        // GET: /account/confirm-email
        [HttpGet("confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
                return View("error");

            var user = await this._UserManager.FindByIdAsync(userId);
            if (user == null)
                return View("error");

            var result = await this._UserManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "confirm-email" : "error");
        }

        // GET: /account/forgot-password
        [HttpGet("forgot-password")]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
            => View();

        // POST: /account/forgot-password
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await this._UserManager.FindByEmailAsync(model.Email);
            if (user == null || !(await this._UserManager.IsEmailConfirmedAsync(user)))
                // Don't reveal that the user does not exist or is not confirmed
                return View("forgot-password-confirmation");

            // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
            // Send an email with this link
            var code = await this._UserManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Action("reset-password", "account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
            await this._EmailSender.SendEmailAsync(model.Email, Resources.EmailMessages.ResetPasswordSubject, string.Format(Resources.EmailMessages.ResetPasswordMessage, callbackUrl));
            return View("forgot-password-confirmation");
        }

        // GET: /account/forgot-password-confirmation
        [HttpGet("forgot-password-confirmation")]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
            => View();

        // GET: /account/reset-password
        [HttpGet("reset-password")]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
            => (code == null) ? View("error") : View();

        // POST: /account/reset-password
        [HttpPost("reset-password")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);
            var user = await this._UserManager.FindByEmailAsync(model.Email);

            if (user == null)
                // Don't reveal that the user does not exist
                return RedirectToAction("reset-password-confirmation", "account");

            var result = await this._UserManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
                return RedirectToAction("reset-password-confirmation", "account");

            this.AddErrors(result);
            return View();
        }

        // GET: /account/reset-password-confirmation
        [HttpGet("reset-password-confirmation")]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
            =>  View();

        // GET: /account/send-code
        [HttpGet("send-code")]
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
        {
            var user = await this._SignInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return View("error");
            var userFactors = await this._UserManager.GetValidTwoFactorProvidersAsync(user);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        // POST: /account/send-code
        [HttpPost("send-code")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
                return View();

            var user = await this._SignInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return View("error");

            if (model.SelectedProvider == "Authenticator")
                return RedirectToAction("verify-authenticator-code", new { returnUrl = model.ReturnUrl, rememberMe = model.RememberMe });

            // Generate the token and send it
            var code = await this._UserManager.GenerateTwoFactorTokenAsync(user, model.SelectedProvider);
            if (string.IsNullOrWhiteSpace(code))
                return View("error");

            var message = "Your security code is: " + code;
            if (model.SelectedProvider == "Email")
                await this._EmailSender.SendEmailAsync(await this._UserManager.GetEmailAsync(user), "Security Code", message);
            else if (model.SelectedProvider == "Phone")
                await this._SmsSender.SendSmsAsync(await this._UserManager.GetPhoneNumberAsync(user), message);

            return RedirectToAction("verify-code", new { provider = model.SelectedProvider, returnUrl = model.ReturnUrl, rememberMe = model.RememberMe });
        }

        // GET: /account/verify-code
        [HttpGet("verify-code")]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyCode(string provider, bool rememberMe, string returnUrl = null)
        {
            // Require that the user has already logged in via username/password or external login
            var user = await this._SignInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return View("error");
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        // POST: /account/verify-code
        [HttpPost("verify-code")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            // The following code protects for brute force attacks against the two factor codes.
            // If a user enters incorrect codes for a specified amount of time then the user account
            // will be locked out for a specified amount of time.
            var result = await this._SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe, model.RememberBrowser);
            if (result.Succeeded)
                return RedirectToLocal(model.ReturnUrl);

            if (result.IsLockedOut)
            {
                this._Logger.LogWarning(7, "User account locked out.");
                return View("lockout");
            }


            ModelState.AddModelError(string.Empty, "Invalid code.");
            return View(model);
        }

        // GET: /account/verify-authenticator-code
        [HttpGet("verify-authenticator-code")]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            // Require that the user has already logged in via username/password or external login
            var user = await this._SignInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return View("error");
            return View(new VerifyAuthenticatorCodeViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        // POST: /account/verify-authenticator-code
        [HttpPost("verify-authenticator-code")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorCodeViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            // The following code protects for brute force attacks against the two factor codes.
            // If a user enters incorrect codes for a specified amount of time then the user account
            // will be locked out for a specified amount of time.
            var result = await this._SignInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, model.RememberBrowser);
            if (result.Succeeded)
                return RedirectToLocal(model.ReturnUrl);

            if (result.IsLockedOut)
            {
                this._Logger.LogWarning(7, "User account locked out.");
                return View("lockout");
            }

            ModelState.AddModelError(string.Empty, "Invalid code.");
            return View(model);
        }

        // GET: /account/use-recovery-code
        [HttpGet("use-recovery-code")]
        [AllowAnonymous]
        public async Task<IActionResult> UseRecoveryCode(string returnUrl = null)
        {
            // Require that the user has already logged in via username/password or external login
            var user = await this._SignInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return View("error");
            return View(new UseRecoveryCodeViewModel { ReturnUrl = returnUrl });
        }

        // POST: /account/use-recovery-code
        [HttpPost("use-recovery-code")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UseRecoveryCode(UseRecoveryCodeViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var result = await this._SignInManager.TwoFactorRecoveryCodeSignInAsync(model.Code);
            if (result.Succeeded)
                return this.RedirectToLocal(model.ReturnUrl);

            ModelState.AddModelError(string.Empty, "Invalid code.");
            return View(model);
        }


        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string ReturnUrl)
        {
            var context = await this._Interaction.GetAuthorizationContextAsync(ReturnUrl);
            if (context?.IdP != null && await this._SchemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = ReturnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };

                return vm;
            }

            var schemes = await this._SchemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null || (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase)))
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await this._ClientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = ReturnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await this.BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await this._Interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await this._Interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == false)
                return vm;

            var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
            if (idp == null || idp == IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                return vm;

            var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
            if (!providerSupportsSignout)
                return vm;

            // if there's no current logout context, we need to create one
            // this captures necessary info from the current logged in user
            // before we signout and redirect away to the external IdP for signout
            if (vm.LogoutId == null)
                vm.LogoutId = await this._Interaction.CreateLogoutContextAsync();

            vm.ExternalAuthenticationScheme = idp;

            return vm;
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string ReturnUrl)
            => Url.IsLocalUrl(ReturnUrl) ? Redirect(ReturnUrl) : (IActionResult)RedirectToAction(nameof(HomeController.Index), "Home");
    }
}
