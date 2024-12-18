using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Services;

namespace SecureVault.Web.Pages.Account
{
    [AllowAnonymous]
    public class TwoFactorVerifyModel : PageModel
    {
        private readonly ITwoFactorAuthService _twoFactorAuthService;
        private readonly IUserService _userService;
        private readonly IAuthenticationService _authenticationService;

        public TwoFactorVerifyModel(
            ITwoFactorAuthService twoFactorAuthService,
            IUserService userService,
            IAuthenticationService authenticationService)
        {
            _twoFactorAuthService = twoFactorAuthService;
            _userService = userService;
            _authenticationService = authenticationService;
        }

        [BindProperty]
        public string Code { get; set; }

        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public IActionResult OnGet()
        {
            // Ensure we have a pending 2FA session
            var userId = HttpContext.Session.GetString("PendingTwoFactorUserId");
            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToPage("./Login");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var userId = HttpContext.Session.GetString("PendingTwoFactorUserId");
            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToPage("./Login");
            }

            try
            {
                var isValid = await _twoFactorAuthService.ValidateCodeAsync(userId, Code);
                if (!isValid)
                {
                    // Try recovery code if TOTP code fails
                    isValid = await _twoFactorAuthService.ValidateRecoveryCodeAsync(userId, Code);
                    if (!isValid)
                    {
                        ErrorMessage = "Invalid verification code";
                        return Page();
                    }
                }

                // Clear the pending 2FA session
                HttpContext.Session.Remove("PendingTwoFactorUserId");

                // Complete the sign-in process
                await _authenticationService.SignInAsync(userId);

                if (string.IsNullOrEmpty(ReturnUrl) || !Url.IsLocalUrl(ReturnUrl))
                {
                    return RedirectToPage("/Index");
                }

                return LocalRedirect(ReturnUrl);
            }
            catch (Exception ex)
            {
                ErrorMessage = "An error occurred during verification. Please try again.";
                return Page();
            }
        }
    }
}
