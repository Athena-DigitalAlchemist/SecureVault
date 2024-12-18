using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureVault.Core.Interfaces;

namespace SecureVault.Web.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly IUserService _userService;
        private readonly IAuthenticationService _authenticationService;
        private readonly ITwoFactorAuthService _twoFactorAuthService;

        public LoginModel(
            IUserService userService,
            IAuthenticationService authenticationService,
            ITwoFactorAuthService twoFactorAuthService)
        {
            _userService = userService;
            _authenticationService = authenticationService;
            _twoFactorAuthService = twoFactorAuthService;
        }

        [BindProperty]
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [BindProperty]
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [BindProperty]
        public bool RememberMe { get; set; }

        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public void OnGet()
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                var loginResult = await _authenticationService.ValidateCredentialsAsync(Email, Password);
                if (!loginResult.IsValid)
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }

                var userId = loginResult.UserId;

                // Check if 2FA is enabled for the user
                if (await _twoFactorAuthService.IsTwoFactorEnabledAsync(userId))
                {
                    // Store the user ID in session for the 2FA verification step
                    HttpContext.Session.SetString("PendingTwoFactorUserId", userId);

                    // Redirect to 2FA verification page
                    return RedirectToPage("./TwoFactorVerify", new { returnUrl = ReturnUrl });
                }

                // If 2FA is not enabled, complete the sign-in process
                await _authenticationService.SignInAsync(userId, RememberMe);

                if (string.IsNullOrEmpty(ReturnUrl) || !Url.IsLocalUrl(ReturnUrl))
                {
                    return RedirectToPage("/Index");
                }

                return LocalRedirect(ReturnUrl);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "An error occurred during login. Please try again.");
                return Page();
            }
        }
    }

    public class LoginResult
    {
        public bool IsValid { get; set; }
        public string UserId { get; set; }
    }
}
