using aspapp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenQA.Selenium.BiDi.Modules.Input;
using System.ComponentModel.DataAnnotations;

namespace aspapp.Areas.Identity.Pages.Account
{
    public class CaptchaLogin : PageModel
    {
        private readonly SignInManager<aspapp.ApplicationUse.ApplicationUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly TripContext _tripContext;
        private readonly UserManager<aspapp.ApplicationUse.ApplicationUser> _userManager;

        public CaptchaLogin(SignInManager<aspapp.ApplicationUse.ApplicationUser> signInManager, ILogger<LoginModel> logger,
            TripContext tripContext, UserManager<aspapp.ApplicationUse.ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _logger = logger;
            _tripContext = tripContext;
            _userManager = userManager;
        }


        [BindProperty]
        public string CaptchaInput { get; set; }
        public string CaptchaReversed { get; set; }


        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; }

            [Required, DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null, string CaptchaInput = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            

            returnUrl ??= Url.Content("~/");
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null, string CaptchaInput = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (!ModelState.IsValid)
                return Page();

            var sessionCaptcha = HttpContext.Session.GetString("CaptchaCode");
            char[] charArray = sessionCaptcha.ToCharArray();
            Array.Reverse(charArray);
            string reversed = new string(charArray);

            if (string.IsNullOrEmpty(sessionCaptcha) || CaptchaInput != reversed)
            {
                ModelState.AddModelError(string.Empty, "Nieprawidłowy kod CAPTCHA.");
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Użytkownik nie istnieje.");
                return Page();
            }

            var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                _logger.LogInformation("Użytkownik zalogowany.");

                var now = DateTime.UtcNow;

                if (user != null)
                {
                    user.LastActivity = now;
                    await _userManager.UpdateAsync(user);
                }

                return LocalRedirect(returnUrl);
            }

            if (result.RequiresTwoFactor)
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });

            if (result.IsLockedOut)
            {
                _logger.LogWarning("Konto zablokowane.");
                return RedirectToPage("./Lockout");
            }

            ModelState.AddModelError(string.Empty, "Nieprawidłowy login lub hasło.");
            return Page();
        }
    }
}
