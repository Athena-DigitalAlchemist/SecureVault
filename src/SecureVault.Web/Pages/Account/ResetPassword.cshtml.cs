using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.Web.Pages.Account
{
    [AllowAnonymous]
    public class ResetPasswordModel : PageModel
    {
        private readonly IPasswordResetService _passwordResetService;

        public ResetPasswordModel(IPasswordResetService passwordResetService)
        {
            _passwordResetService = passwordResetService;
        }

        [BindProperty]
        public string Token { get; set; }

        [BindProperty]
        [Required]
        [StringLength(100, MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$",
            ErrorMessage = "Password must be at least 8 characters and contain at least one uppercase letter, one lowercase letter, one number, and one special character.")]
        public string NewPassword { get; set; }

        [BindProperty]
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public bool IsTokenValid { get; set; }

        public async Task<IActionResult> OnGetAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return RedirectToPage("./Login");
            }

            Token = token;
            IsTokenValid = await _passwordResetService.ValidateResetTokenAsync(token);

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                IsTokenValid = true;
                return Page();
            }

            var resetRequest = new PasswordResetRequest
            {
                Token = Token,
                NewPassword = NewPassword,
                ConfirmPassword = ConfirmPassword
            };

            var result = await _passwordResetService.ResetPasswordAsync(resetRequest);
            if (result.Success)
            {
                TempData["SuccessMessage"] = "Your password has been reset successfully. Please log in with your new password.";
                return RedirectToPage("./Login");
            }

            ErrorMessage = result.Error;
            IsTokenValid = true;
            return Page();
        }
    }
}
