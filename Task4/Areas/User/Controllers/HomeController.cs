using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Task4.Data;
using Task4.Models;

namespace Task4.Areas.User.Controllers
{
    [Authorize]
    [Area("User")]
    public class HomeController: Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ApplicationDbContext _context;
        private readonly SignInManager<IdentityUser> _signInManager;

        public HomeController(ILogger<HomeController> logger,
            ApplicationDbContext context,
            SignInManager<IdentityUser> signInManager)
        {
            _logger = logger;
            _context = context;
            _signInManager = signInManager;
        }
        public async Task<IActionResult> Index()
        {
            await LogoutIfLockedOrRemoved();
            return View(_context.Users);
        }

        private async Task LogoutIfLockedOrRemoved()
        {
            var claimsIdentity = (ClaimsIdentity?)User.Identity;

            var claim = claimsIdentity?.FindFirst(ClaimTypes.NameIdentifier);
            
            if (claim != null)
            {
                var user = _context.Users.FirstOrDefault(u => u.Id == claim.Value);

                if (user == null || (user is { LockoutEnd: { } } && user.LockoutEnd > DateTime.Now))
                {
                    await _signInManager.SignOutAsync();

                    Response.Redirect("/");
                }
            }
        }

        public async Task<IActionResult> Lock(string[] selectedUsers)
        {
            await LogoutIfLockedOrRemoved();

            foreach (var id in selectedUsers)
            {
                if (string.IsNullOrEmpty(id))
                {
                    return NotFound();
                }

                var user = await _context.Users.FindAsync(id);

                if (user == null)
                {
                    return NotFound();
                }

                user.LockoutEnd = DateTime.Now.AddYears(999);
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        
        [HttpPost]
        public async Task<IActionResult> UnLock(string[] selectedUsers)
        {
            await LogoutIfLockedOrRemoved();

            foreach (var id in selectedUsers)
            {
                if (string.IsNullOrEmpty(id))
                {
                    return NotFound();
                }

                var user = await _context.Users.FindAsync(id);

                if (user == null)
                {
                    return NotFound();
                }

                user.LockoutEnd = null;
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Delete(string[] selectedUsers)
        {
            foreach (var id in selectedUsers)
            {
                if (string.IsNullOrEmpty(id))
                {
                    return NotFound();
                }

                var user = await _context.Users.FindAsync(id);

                if (user == null)
                {
                    return NotFound();
                }

                await _signInManager.UserManager.DeleteAsync(user);
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}