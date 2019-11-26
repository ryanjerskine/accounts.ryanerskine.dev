using System;
using System.Linq;
using System.Threading.Tasks;
using Accounts.RyanErskine.Dev.Models;
using Accounts.RyanErskine.Dev.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Accounts.RyanErskine.Dev.Controllers
{
    [Authorize]
    public class ManageController : Controller
    {
        private readonly UserManager<ApplicationUser> _UserManager;
        private readonly SignInManager<ApplicationUser> _SignInManager;
        private readonly IEmailSender _EmailSender;
        private readonly ISmsSender _SmsSender;
        private readonly ILogger _Logger;

        public ManageController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILogger<ManageController> logger)
        {
            this._UserManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            this._SignInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
            this._EmailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
            this._SmsSender = smsSender ?? throw new ArgumentNullException(nameof(smsSender));
            this._Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // GET: /manage
        [HttpGet]
        public async Task<IActionResult> Index(ManageMessageId? message = null)
        {
            ViewData["StatusMessage"] = message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed." :
                                        message == ManageMessageId.SetPasswordSuccess ? "Your password has been set." :
                                        message == ManageMessageId.SetTwoFactorSuccess ? "Your two-factor authentication provider has been set." :
                                        message == ManageMessageId.Error ? "An error has occurred." :
                                        message == ManageMessageId.AddPhoneSuccess ? "Your phone number was added." :
                                        message == ManageMessageId.RemovePhoneSuccess ? "Your phone number was removed." : "";

            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            var model = new ManageViewModel
            {
                HasPassword = await this._UserManager.HasPasswordAsync(user),
                PhoneNumber = await this._UserManager.GetPhoneNumberAsync(user),
                TwoFactor = await this._UserManager.GetTwoFactorEnabledAsync(user),
                Logins = await this._UserManager.GetLoginsAsync(user),
                BrowserRemembered = await this._SignInManager.IsTwoFactorClientRememberedAsync(user),
                AuthenticatorKey = await this._UserManager.GetAuthenticatorKeyAsync(user)
            };
            return View(model);
        }

        // POST: /manage/remove-login
        [HttpPost("remove-login")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveLogin(RemoveLoginViewModel account)
        {
            ManageMessageId? message = ManageMessageId.Error;
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user == null)
                return RedirectToAction(nameof(ManageLogins), new { message = message });

            var result = await this._UserManager.RemoveLoginAsync(user, account.LoginProvider, account.ProviderKey);
            if (result.Succeeded)
            {
                await this._SignInManager.SignInAsync(user, isPersistent: false);
                message = ManageMessageId.RemoveLoginSuccess;
            }
            return RedirectToAction(nameof(ManageLogins), new { message = message });
        }

        // GET: /manage/add-phone-number
        [HttpGet("add-phone-number")]
        public IActionResult AddPhoneNumber()
            => View();

        // POST: /manage/add-phone-number
        [HttpPost("add-phone-number")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddPhoneNumber(AddPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            // Generate the token and send it
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            var code = await this._UserManager.GenerateChangePhoneNumberTokenAsync(user, model.PhoneNumber);
            await this._SmsSender.SendSmsAsync(model.PhoneNumber, "Your security code is: " + code);
            return RedirectToAction(nameof(VerifyPhoneNumber), new { phoneNumber = model.PhoneNumber });
        }

        // POST: /manage/reset-authenticator-key
        [HttpPost("reset-authenticator-key")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetAuthenticatorKey()
        {
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user != null)
            {
                await this._UserManager.ResetAuthenticatorKeyAsync(user);
                this._Logger.LogInformation(1, "User reset authenticator key.");
            }
            return RedirectToAction(nameof(Index), "manage");
        }

        // POST: /manage/generate-recovery-code
        [HttpPost("generate-recovery-code")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> GenerateRecoveryCode()
        {
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user != null)
            {
                var codes = await this._UserManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 5);
                this._Logger.LogInformation(1, "User generated new recovery code.");
                return View("DisplayRecoveryCodes", new DisplayRecoveryCodesViewModel { Codes = codes });
            }
            return View("Error");
        }

        // POST: /manage/enable-two-factor-authentication
        [HttpPost("enable-two-factor-authentication")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableTwoFactorAuthentication()
        {
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user != null)
            {
                await this._UserManager.SetTwoFactorEnabledAsync(user, true);
                await this._SignInManager.SignInAsync(user, isPersistent: false);
                this._Logger.LogInformation(1, "User enabled two-factor authentication.");
            }
            return RedirectToAction(nameof(Index), "manage");
        }

        // POST: /manage/disable-two-factor-authentication
        [HttpPost("disable-two-factor-authentication")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DisableTwoFactorAuthentication()
        {
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user != null)
            {
                await this._UserManager.SetTwoFactorEnabledAsync(user, false);
                await this._SignInManager.SignInAsync(user, isPersistent: false);
                this._Logger.LogInformation(2, "User disabled two-factor authentication.");
            }
            return RedirectToAction(nameof(Index), "Manage");
        }

        // GET: /manage/verify-phone-number
        [HttpGet("verify-phone-number")]
        public async Task<IActionResult> VerifyPhoneNumber(string phoneNumber)
        {
            var code = await this._UserManager.GenerateChangePhoneNumberTokenAsync(await this._UserManager.GetUserAsync(HttpContext.User), phoneNumber);
            // Send an SMS to verify the phone number
            return phoneNumber == null ? View("error") : View(new VerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
        }

        // POST: /manage/verify-phone-number
        [HttpPost("verify-phone-number")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Failed to verify phone number");
                return View(model);
            }

            var result = await this._UserManager.ChangePhoneNumberAsync(user, model.PhoneNumber, model.Code);
            if (result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Failed to verify phone number");
                return View(model);
            }

            await this._SignInManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction(nameof(Index), new { message = ManageMessageId.AddPhoneSuccess });
        }

        // GET: /manage/remove-phone-number
        [HttpPost("remove-phone-number")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemovePhoneNumber()
        {
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user == null)
                return RedirectToAction(nameof(Index), new { message = ManageMessageId.Error });

            var result = await this._UserManager.SetPhoneNumberAsync(user, null);
            if (!result.Succeeded)
                return RedirectToAction(nameof(Index), new { message = ManageMessageId.Error });

            await this._SignInManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction(nameof(Index), new { message = ManageMessageId.RemovePhoneSuccess });
        }

        // GET: /manage/change-password
        [HttpGet("change-password")]
        public IActionResult ChangePassword()
            => View();

        // POST: /manage/change-password
        [HttpPost("change-password")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user == null)
                return RedirectToAction(nameof(Index), new { message = ManageMessageId.Error });

            var result = await this._UserManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                await this._SignInManager.SignInAsync(user, isPersistent: false);
                this._Logger.LogInformation(3, "User changed their password successfully.");
                return RedirectToAction(nameof(Index), new { message = ManageMessageId.ChangePasswordSuccess });
            }

            AddErrors(result);
            return View(model);
        }

        // GET: /manage/set-password
        [HttpGet("set-password")]
        public IActionResult SetPassword()
            => View();

        // POST: /manage/set-password
        [HttpPost("set-password")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user == null)
                return RedirectToAction(nameof(Index), new { message = ManageMessageId.Error });

            var result = await this._UserManager.AddPasswordAsync(user, model.NewPassword);
            if (result.Succeeded)
            {
                await this._SignInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction(nameof(Index), new { message = ManageMessageId.SetPasswordSuccess });
            }
            AddErrors(result);
            return View(model);
        }

        //GET: /manage/manage-logins
        [HttpGet("manage-logins")]
        public async Task<IActionResult> ManageLogins(ManageMessageId? message = null)
        {
            ViewData["StatusMessage"] = message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed." :
                                        message == ManageMessageId.AddLoginSuccess ? "The external login was added." :
                                        message == ManageMessageId.Error ? "An error has occurred." : "";
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user == null)
                return View("Error");
            var userLogins = await this._UserManager.GetLoginsAsync(user);
            var schemes = await this._SignInManager.GetExternalAuthenticationSchemesAsync();
            var otherLogins = schemes.Where(auth => userLogins.All(ul => auth.Name != ul.LoginProvider)).ToList();
            ViewData["ShowRemoveButton"] = user.PasswordHash != null || userLogins.Count > 1;
            return View(new ManageLoginsViewModel
            {
                CurrentLogins = userLogins,
                OtherLogins = otherLogins
            });
        }

        // POST: /manage/link-login
        [HttpPost("link-login")]
        [ValidateAntiForgeryToken]
        public IActionResult LinkLogin(string provider)
        {
            // Request a redirect to the external login provider to link a login for the current user
            var redirectUrl = Url.Action("LinkLoginCallback", "Manage");
            var properties = this._SignInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, this._UserManager.GetUserId(User));
            return Challenge(properties, provider);
        }

        // GET: /manage/link-login-callback
        [HttpGet("link-login-callback")]
        public async Task<ActionResult> LinkLoginCallback()
        {
            var user = await this._UserManager.GetUserAsync(HttpContext.User);
            if (user == null)
                return View("Error");

            var info = await _SignInManager.GetExternalLoginInfoAsync(await this._UserManager.GetUserIdAsync(user));
            if (info == null)
                return RedirectToAction(nameof(ManageLogins), new { message = ManageMessageId.Error });

            var result = await this._UserManager.AddLoginAsync(user, info);
            var message = result.Succeeded ? ManageMessageId.AddLoginSuccess : ManageMessageId.Error;
            return RedirectToAction(nameof(ManageLogins), new { message = message });
        }


        /****************************************/
        /* helper APIs for the ManageController */
        /****************************************/
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        public enum ManageMessageId
        {
            AddPhoneSuccess,
            AddLoginSuccess,
            ChangePasswordSuccess,
            SetTwoFactorSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            RemovePhoneSuccess,
            Error
        }
    }
}
