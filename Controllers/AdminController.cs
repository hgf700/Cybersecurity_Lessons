using aspapp.Models;
using aspapp.Models.VM;
using aspapp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Serilog.Context;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace aspapp.Controllers
{
    [Authorize(Roles = "ADMIN")]
    [Route("admin")]
    public class AdminController : Controller
    {
        private readonly SignInManager<aspapp.ApplicationUse.ApplicationUser> _signInManager;
        private readonly UserManager<aspapp.ApplicationUse.ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly TripContext _context;
        private readonly ILogger<AdminController> _logger;

        public AdminController(UserManager<aspapp.ApplicationUse.ApplicationUser> userManager,
                               SignInManager<ApplicationUse.ApplicationUser> signInManager,
                               IEmailSender emailSender,
                               TripContext context,
                               ILogger<AdminController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _context = context;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            ViewBag.Message = $"Zalogowano jako {user.Email}";

            var userList = new List<UserWithRoleViewModel>();
            var allUsers = _userManager.Users.ToList();

            foreach (var u in allUsers)
            {
                var roles = await _userManager.GetRolesAsync(u);
                userList.Add(new UserWithRoleViewModel
                {
                    Id = u.Id,
                    Email = u.Email,
                    UserName = u.UserName,
                    Roles = roles.ToList()
                });
            }

            return View(userList);
        }

        [HttpGet("CreateUser")]
        public async Task<IActionResult> CreateUser() => View();

        [HttpPost("CreateUser")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateUser(CreateUser model)
        {
            if (!ModelState.IsValid)
            {
                foreach (var e in ModelState.Values.SelectMany(v => v.Errors))
                    Console.WriteLine($"❌ {e.ErrorMessage}");
            }



            var targetUser = await _userManager.FindByEmailAsync(model.Email);
            if (targetUser != null)
            {
                ModelState.AddModelError(string.Empty, "Użytkownik o podanym adresie e-mail już istnieje.");
                return View(model);
            }

            if (model.IsOneTimePassword)
            {

                var len = model.Email.Length;
                var x = 65;
                var value = len * x;
                var logValue = Math.Log(value);
                var otp = $"{logValue:F11}Aa";
                model.Password = otp;
                model.ConfirmPassword = otp;

                ModelState.Remove(nameof(model.Password));
                ModelState.Remove(nameof(model.ConfirmPassword));
                ModelState.ClearValidationState(nameof(model.Password));
                ModelState.ClearValidationState(nameof(model.ConfirmPassword));
                TryValidateModel(model);

                Console.WriteLine($"📨 IsOneTimePassword = {model.IsOneTimePassword}");

            }
            else
            {
                if (model.Password != model.ConfirmPassword)
                {
                    ModelState.AddModelError(string.Empty, "Hasła nie są takie same.");
                    return View(model);
                }
            }
            Console.WriteLine($"📨 IsOneTimePassword = {model.IsOneTimePassword}");

            //ModelState.Remove("UserName");
            //ModelState.Remove(nameof(model.UserName));

            var identityUser = new aspapp.ApplicationUse.ApplicationUser
            {
                UserName = model.Email.Trim(),
                Email = model.Email.Trim()
            };

            Console.WriteLine($"📧 Email: {model.Email}");
            Console.WriteLine($"👤 UserName (to samo co email): {identityUser.UserName}");
            Console.WriteLine($"🔐 Password: {model.Password}");

            

            var result = await _userManager.CreateAsync(identityUser, model.Password);
            await _userManager.SetLockoutEndDateAsync(identityUser, null);
            await _userManager.ResetAccessFailedCountAsync(identityUser);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    Console.WriteLine($"❌ Identity Error: {error.Description}");
            }


            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                using (LogContext.PushProperty("Action", "CreateUser failed"))
                using (LogContext.PushProperty("Role", "Admin"))
                {
                    _logger.LogInformation("Action executed by {User}", model.Email);
                }

                return View(model);
            }

            await _userManager.AddToRoleAsync(identityUser, "User");
            TempData["Message"] = "Użytkownik został utworzony.";

            using (LogContext.PushProperty("Action", "CreateUser succeeded"))
            using (LogContext.PushProperty("Role", "User"))
            {
                _logger.LogInformation("Action executed for {User}", identityUser.Email);
            }

            // Email confirmation
            string returnUrl = Url.Content("~/admin");
            var userId = await _userManager.GetUserIdAsync(identityUser);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(identityUser);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callbackUrl = Url.Page(
                "/Account/ConfirmEmail",
                pageHandler: null,
                values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(model.Email, "Confirm your email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            if (_userManager.Options.SignIn.RequireConfirmedAccount)
                return RedirectToPage("RegisterConfirmation", new { email = model.Email, returnUrl = returnUrl });
            else
                return LocalRedirect(returnUrl);
        }

        [HttpGet("EditAdminPassword")]
        public async Task<IActionResult> EditAdminPassword() => View();

        [HttpPost("EditAdminPassword")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditAdminPassword(EditPassword model)
        {
            if (!ModelState.IsValid)
                return View(model);


            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            if (!await _userManager.CheckPasswordAsync(user, model.OldPassword))
            {
                ModelState.AddModelError(string.Empty, "Niepoprawne obecne hasło.");
                return View(model);
            }

            if (model.NewPassword != model.ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Nowe hasła nie są takie same.");
                return View(model);
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                using (LogContext.PushProperty("Action", "EditAdminPassword failed"))
                using (LogContext.PushProperty("Role", "ADMIN"))
                {
                    _logger.LogInformation("Action executed for {User}", user.Email);
                }

                return View(model);
            }

            await _signInManager.RefreshSignInAsync(user);

            using (LogContext.PushProperty("Action", "EditAdminPassword succeeded"))
            using (LogContext.PushProperty("Role", "ADMIN"))
            {
                _logger.LogInformation("Action executed for {User}", user.Email);
            }

            TempData["Message"] = "Hasło zostało pomyślnie zmienione.";
            return RedirectToAction("Index");
        }

        [HttpGet("EditAdminPasswordReCAPTCHA")]
        public async Task<IActionResult> EditAdminPasswordReCAPTCHA() {
            
            
            
            return View();
        }

        [HttpPost("EditAdminPasswordReCAPTCHA")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditAdminPasswordReCAPTCHA(EditPassword model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            if (!await _userManager.CheckPasswordAsync(user, model.OldPassword))
            {
                ModelState.AddModelError(string.Empty, "Niepoprawne obecne hasło.");
                return View(model);
            }

            if (model.NewPassword != model.ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Nowe hasła nie są takie same.");
                return View(model);
            }

            var recaptchaResponse = Request.Form["g-recaptcha-response"];
            string secretKey = Environment.GetEnvironmentVariable("secret_key");

            using var httpClient = new HttpClient();
            var response = await httpClient.PostAsync(
                "https://www.google.com/recaptcha/api/siteverify",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "secret", secretKey },
                    { "response", recaptchaResponse }
                })
            );

            var json = await response.Content.ReadAsStringAsync();
            var captchaResult = System.Text.Json.JsonDocument.Parse(json);
            var successCaptcha = captchaResult.RootElement.GetProperty("success").GetBoolean();


            if (!successCaptcha)
            {
                ModelState.AddModelError(string.Empty, "Weryfikacja reCAPTCHA nie powiodła się.");
                return View(model);
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                using (LogContext.PushProperty("Action", "EditAdminPassword failed"))
                using (LogContext.PushProperty("Role", "ADMIN"))
                {
                    _logger.LogInformation("Action executed for {User}", user.Email);
                }

                return View(model);
            }

            await _signInManager.RefreshSignInAsync(user);

            using (LogContext.PushProperty("Action", "EditAdminPassword succeeded"))
            using (LogContext.PushProperty("Role", "ADMIN"))
            {
                _logger.LogInformation("Action executed for {User}", user.Email);
            }

            TempData["Message"] = "Hasło zostało pomyślnie zmienione.";
            return RedirectToAction("Index");
        }

        [HttpGet("EditAdmin")]
        public async Task<IActionResult> EditAdmin() => View();

        [HttpPost("EditAdmin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditAdmin(EditAdmin model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            var existingUserByName = await _userManager.FindByNameAsync(model.UserName);
            if (existingUserByName != null && existingUserByName.Id != user.Id)
            {
                ModelState.AddModelError("UserName", "Ta nazwa użytkownika jest już zajęta.");
                return View(model);
            }

            user.UserName = model.UserName;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                foreach (var error in updateResult.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                using (Serilog.Context.LogContext.PushProperty("Action", "EditAdmin failed"))
                using (Serilog.Context.LogContext.PushProperty("Role", "ADMIN"))
                {
                    _logger.LogInformation("Action executed for {User}", user.Email);
                }

                return View(model);
            }

            using (Serilog.Context.LogContext.PushProperty("Action", "EditAdmin succeeded"))
            using (Serilog.Context.LogContext.PushProperty("Role", "ADMIN"))
            {
                _logger.LogInformation("Action executed for {User}", user.Email);
            }

            ViewBag.Message = "Dane administratora zostały pomyślnie zaktualizowane.";
            return View(model);
        }

        [HttpGet("BlockAccount")]
        public async Task<IActionResult> BlockAccount() => View();

        [HttpPost("BlockAccount")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> BlockAccount(BlockAccount model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var admin = await _userManager.GetUserAsync(User);
            var targetUser = await _userManager.FindByEmailAsync(model.Email);
            if (targetUser == null || admin == null)
            {
                ModelState.AddModelError(string.Empty, "Niepoprawny użytkownik.");
                return View(model);
            }

            if (admin.Id == targetUser.Id)
            {
                ModelState.AddModelError(string.Empty, "Nie możesz zablokować własnego konta administracyjnego.");
                return View();
            }

            var daysToBlock = model.Days > 0 ? model.Days : 30;
            await _userManager.SetLockoutEndDateAsync(targetUser, DateTimeOffset.UtcNow.AddDays(daysToBlock));
            await _userManager.UpdateAsync(targetUser);

            using (Serilog.Context.LogContext.PushProperty("Action", "BlockAccount succeeded"))
            using (Serilog.Context.LogContext.PushProperty("Role", "ADMIN"))
            {
                _logger.LogInformation("Action executed for {User}", targetUser.Email);
            }

            ViewBag.Message = $"Użytkownik {targetUser.Email} został zablokowany na {daysToBlock} dni.";
            return View(model);
        }

        [HttpGet("DeleteAccount")]
        public async Task<IActionResult> DeleteAccount() => View();

        [HttpPost("DeleteAccount")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteAccount(DeleteAccount model)
        {
            var admin = await _userManager.GetUserAsync(User);
            var targetUser = await _userManager.FindByEmailAsync(model.email);
            if (targetUser == null || admin == null)
            {
                ModelState.AddModelError(string.Empty, "Niepoprawny użytkownik.");
                return View(model);
            }

            if (admin.Id == targetUser.Id)
            {
                ModelState.AddModelError(string.Empty, "Nie możesz usunąć własnego konta administracyjnego.");
                return View();
            }

            var result = await _userManager.DeleteAsync(targetUser);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);
                return View(model);
            }

            using (Serilog.Context.LogContext.PushProperty("Action", "DeleteAccount succeeded"))
            using (Serilog.Context.LogContext.PushProperty("Role", "ADMIN"))
            {
                _logger.LogInformation("Action executed for {User}", targetUser.Email);
            }

            TempData["Message"] = "Użytkownik został usunięty.";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet("PasswordRequirments")]
        public async Task<IActionResult> PasswordRequirments() => View();

        [HttpPost("PasswordRequirments")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> PasswordRequirments(SecuritySettings model)
        {
            if (!ModelState.IsValid)
            {
                foreach (var e in ModelState.Values.SelectMany(v => v.Errors))
                    Console.WriteLine($"❌ {e.ErrorMessage}");
                return View(model);
            }

            var admin = await _userManager.GetUserAsync(User);
            if (admin == null)
                return NotFound("Zalogowany administrator nie został znaleziony.");

            var existingPolicy = await _context.SecuritySettings.FirstOrDefaultAsync();

            if (existingPolicy != null)
            {
                if (model.RequiredLength != null)
                    existingPolicy.RequiredLength = model.RequiredLength.Value;
                if (model.RequireDigit != null)
                    existingPolicy.RequireDigit = model.RequireDigit.Value;
                if (model.RequireUppercase != null)
                    existingPolicy.RequireUppercase = model.RequireUppercase.Value;
                if (model.RequireLowercase != null)
                    existingPolicy.RequireLowercase = model.RequireLowercase.Value;
                if (model.RequireNonAlphanumeric != null)
                    existingPolicy.RequireNonAlphanumeric = model.RequireNonAlphanumeric.Value;
                if (model.PasswordValidity != null)
                    existingPolicy.PasswordValidity = model.PasswordValidity.Value;
                if (model.LimitOfWrongPasswords != null)
                    existingPolicy.LimitOfWrongPasswords = model.LimitOfWrongPasswords;
                if (model.TimeOfInactivity != null)
                    existingPolicy.TimeOfInactivity = model.TimeOfInactivity.Value;

                _context.SecuritySettings.Update(existingPolicy);
            }
            else
            {
                var policy = new SecuritySettings
                {
                    Id = 1,
                    RequiredLength = model.RequiredLength,
                    RequireDigit = model.RequireDigit,
                    RequireUppercase = model.RequireUppercase,
                    RequireLowercase = model.RequireLowercase,
                    RequireNonAlphanumeric = model.RequireNonAlphanumeric,
                    PasswordValidity = model.PasswordValidity,
                    LimitOfWrongPasswords = model.LimitOfWrongPasswords,
                    TimeOfInactivity = model.TimeOfInactivity,
                };
                await _context.SecuritySettings.AddAsync(policy);
            }

            var changes = await _context.SaveChangesAsync();

            if (changes > 0)
            {
                using (Serilog.Context.LogContext.PushProperty("Action", "PasswordRequirments saved successfully"))
                using (Serilog.Context.LogContext.PushProperty("Role", "ADMIN"))
                {
                    _logger.LogInformation("Action executed for {User}", admin.Email);
                }

                TempData["Message"] = "✅ Polityka haseł została zapisana pomyślnie.";
                return RedirectToAction(nameof(PasswordRequirments));
            }

            ModelState.AddModelError(string.Empty, "⚠️ Nie udało się zapisać zmian w bazie danych.");
            using (Serilog.Context.LogContext.PushProperty("Action", "PasswordRequirments failed"))
            using (Serilog.Context.LogContext.PushProperty("Role", "ADMIN"))
            {
                _logger.LogInformation("Action executed for {User}", admin.Email);
            }

            return View(model);
        }

        [HttpGet("ApplicationLogs")]
        public async Task<IActionResult> ApplicationLogs()
        {
            var logs = await _context.Logs
                .OrderByDescending(l => l.TimeStamp)
                .Take(200) // ograniczenie, żeby nie przeciążyć strony
                .ToListAsync();

            if (!logs.Any())
            {
                TempData["Message"] = "Brak dostępnych logów w bazie danych.";
                return View(new List<Logs>()); // zwróć pustą listę zamiast 404
            }

            return View(logs);
        }

        [HttpGet("ReadingFiles")]
        public async Task<IActionResult> ReadingFiles()
        {
            var path = Path.Combine(Directory.GetCurrentDirectory(), "App_Data");

            var files = Directory.GetFiles(path)
                         .Select(Path.GetFileName)
                         .ToList();

            return View(files);
        }

        [HttpPost("ToggleLicence")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleLicence()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            ViewBag.Message = $"Zalogowano jako {user.Email}";

            if (user.Licence == "demo")
            {
                user.Licence = "full_version";
            }
            else if (user.Licence == "full_version")
            {
                user.Licence = "demo";
            }

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
                return BadRequest("Nie udało się zaktualizować licencji.");

            return RedirectToAction("ReadingFiles");
        }

        private const string key = "TAJNE";

        [HttpPost("ActivateLicense")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ActivateLicense(string licenseKey)
        {
            string decrypted = VigenereCipher.Decipher(licenseKey, key);

            if (decrypted == "FULL_VERSION")
            {
                var user = await _userManager.GetUserAsync(User);
                user.Licence = "full_version";
                await _userManager.UpdateAsync(user);

                ViewBag.Message = "Licencja aktywowana! Masz pełną wersję.";
            }
            else
            {
                ViewBag.Message = "❌ Nieprawidłowy klucz licencyjny.";
            }

            return RedirectToAction("ReadingFiles");
        }

        [HttpGet("DownloadFile")]
        public async Task<IActionResult> DownloadFile(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                return BadRequest("Brak nazwy pliku.");

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            if (user.Licence == "demo" && Path.GetExtension(fileName).ToLower() != ".txt")
            {
                return Content("❌ Wersja DEMO umożliwia otwieranie tylko plików TXT.");
            }

            var folderPath = Path.Combine(Directory.GetCurrentDirectory(), "App_Data");
            var fullPath = Path.Combine(folderPath, fileName);

            if (!System.IO.File.Exists(fullPath))
                return NotFound();

            return File(System.IO.File.ReadAllBytes(fullPath), "application/octet-stream", fileName);
        }

        [HttpGet("FakeEndpoint")]
        public async Task<IActionResult> FakeEndpoint()
        {
            return View();
        }

    }
}
