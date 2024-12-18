using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using System;
using System.Threading.Tasks;

namespace SecureVault.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthenticationService _authService;
        private readonly IUserService _userService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthenticationService authService,
            IUserService userService,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _userService = userService;
            _logger = logger;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var isAuthenticated = await _authService.AuthenticateUserAsync(request.Username, request.Password);
                if (!isAuthenticated)
                {
                    return Unauthorized("Invalid username or password");
                }

                var user = await _userService.GetUserByUsernameAsync(request.Username);
                // Generate JWT token here
                var token = ""; // TODO: Implement JWT token generation

                return Ok(new { token });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return StatusCode(500, "An error occurred during login");
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            try
            {
                var existingUser = await _userService.GetUserByUsernameAsync(request.Username);
                if (existingUser != null)
                {
                    return BadRequest("Username already exists");
                }

                var user = await _userService.CreateUserAsync(request.Username, request.Password, request.Email);
                return Ok(new { userId = user.Id });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration");
                return StatusCode(500, "An error occurred during registration");
            }
        }

        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            try
            {
                var userId = User.Identity.Name; // Assuming we store user ID in the Name claim
                var success = await _authService.ChangePasswordAsync(userId, request.CurrentPassword, request.NewPassword);
                
                if (!success)
                {
                    return BadRequest("Invalid current password");
                }

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password");
                return StatusCode(500, "An error occurred while changing password");
            }
        }

        [HttpPost("reset-password-request")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] ResetPasswordRequest request)
        {
            try
            {
                var user = await _userService.GetUserByEmailAsync(request.Email);
                if (user == null)
                {
                    // Return OK even if user doesn't exist to prevent email enumeration
                    return Ok();
                }

                // Generate and send reset token
                // Implementation details will depend on your IPasswordResetService
                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error requesting password reset");
                return StatusCode(500, "An error occurred while requesting password reset");
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordConfirmation request)
        {
            try
            {
                var success = await _authService.ResetPasswordAsync(request.UserId, request.ResetToken, request.NewPassword);
                if (!success)
                {
                    return BadRequest("Invalid or expired reset token");
                }

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password");
                return StatusCode(500, "An error occurred while resetting password");
            }
        }
    }

    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
    }

    public class ChangePasswordRequest
    {
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ResetPasswordRequest
    {
        public string Email { get; set; }
    }

    public class ResetPasswordConfirmation
    {
        public string UserId { get; set; }
        public string ResetToken { get; set; }
        public string NewPassword { get; set; }
    }
}
