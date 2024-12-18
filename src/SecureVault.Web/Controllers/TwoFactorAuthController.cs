using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.Web.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class TwoFactorAuthController : ControllerBase
    {
        private readonly ITwoFactorAuthService _twoFactorAuthService;
        private readonly IUserService _userService;

        public TwoFactorAuthController(
            ITwoFactorAuthService twoFactorAuthService,
            IUserService userService)
        {
            _twoFactorAuthService = twoFactorAuthService;
            _userService = userService;
        }

        [HttpGet("setup")]
        public async Task<ActionResult<TwoFactorSetupInfo>> InitiateSetup()
        {
            try
            {
                var userId = _userService.GetCurrentUserId();
                if (await _twoFactorAuthService.IsTwoFactorEnabledAsync(userId))
                {
                    return BadRequest("Two-factor authentication is already enabled");
                }

                var setupInfo = await _twoFactorAuthService.InitiateTwoFactorSetupAsync(userId);
                return Ok(setupInfo);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error setting up 2FA: {ex.Message}");
            }
        }

        [HttpPost("setup/verify")]
        public async Task<ActionResult> VerifySetup([FromBody] TwoFactorVerificationRequest request)
        {
            try
            {
                var userId = _userService.GetCurrentUserId();
                if (await _twoFactorAuthService.IsTwoFactorEnabledAsync(userId))
                {
                    return BadRequest("Two-factor authentication is already enabled");
                }

                var success = await _twoFactorAuthService.SetupTwoFactorAsync(userId, request.Code);
                if (!success)
                {
                    return BadRequest("Invalid verification code");
                }

                return Ok(new { message = "Two-factor authentication enabled successfully" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error verifying 2FA setup: {ex.Message}");
            }
        }

        [HttpPost("verify")]
        public async Task<ActionResult> Verify([FromBody] TwoFactorVerificationRequest request)
        {
            try
            {
                var userId = _userService.GetCurrentUserId();
                var success = await _twoFactorAuthService.ValidateCodeAsync(userId, request.Code);
                
                if (!success)
                {
                    // Try recovery code if TOTP code fails
                    success = await _twoFactorAuthService.ValidateRecoveryCodeAsync(userId, request.Code);
                    if (!success)
                    {
                        return BadRequest("Invalid verification code");
                    }
                }

                return Ok(new { message = "Verification successful" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error verifying 2FA code: {ex.Message}");
            }
        }

        [HttpPost("disable")]
        public async Task<ActionResult> Disable()
        {
            try
            {
                var userId = _userService.GetCurrentUserId();
                if (!await _twoFactorAuthService.IsTwoFactorEnabledAsync(userId))
                {
                    return BadRequest("Two-factor authentication is not enabled");
                }

                var success = await _twoFactorAuthService.DisableTwoFactorAsync(userId);
                if (!success)
                {
                    return StatusCode(500, "Failed to disable two-factor authentication");
                }

                return Ok(new { message = "Two-factor authentication disabled successfully" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error disabling 2FA: {ex.Message}");
            }
        }

        [HttpGet("status")]
        public async Task<ActionResult<bool>> GetStatus()
        {
            try
            {
                var userId = _userService.GetCurrentUserId();
                var isEnabled = await _twoFactorAuthService.IsTwoFactorEnabledAsync(userId);
                return Ok(new { enabled = isEnabled });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error getting 2FA status: {ex.Message}");
            }
        }
    }

    public class TwoFactorVerificationRequest
    {
        public string Code { get; set; }
    }
}
