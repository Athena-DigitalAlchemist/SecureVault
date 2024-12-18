using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SecureVault.Web.Pages.Security
{
    [Authorize]
    public class TwoFactorModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}
