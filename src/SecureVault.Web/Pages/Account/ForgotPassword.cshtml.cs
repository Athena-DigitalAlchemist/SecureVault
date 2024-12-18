using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureVault.Core.Services;

namespace SecureVault.Web.Pages.Account
{
    [AllowAnonymous]
    public class ForgotPasswordModel : PageModel
    {
        private readonly IPasswordResetService _passwordResetService;

        public ForgotPasswordModel(IPasswordResetService passwordResetService)
        {
            _passwordResetService = passwordResetService;
        }

        [BindProperty]
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public bool RequestSent { get; set; }

        public void OnGet()
        {
            RequestSent = false;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                var result = await _passwordResetService.InitiatePasswordResetAsync(Email);
                RequestSent = true;
                return Page();
            }
            catch (Exception ex)
            {
                ErrorMessage = "An error occurred while processing your request.";
                return Page();
            }
        }
    }
}
