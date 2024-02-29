using Api.Data;
using Api.Models;
using Api.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System;
using System.Threading.Tasks;
using Api.DTOs.Account;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JWTService _jwtService;
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        //private readonly EmailService _emailService;
        //private readonly Context _context;
        //private readonly IConfiguration _config;
        //private readonly HttpClient _facebookHttpClient;

        public AccountController(JWTService jwtService,
            SignInManager<User> signInManager,
            UserManager<User> userManager)
            //EmailService emailService,
            //Context context,
            //IConfiguration config)
        {
            _jwtService = jwtService;
            _signInManager = signInManager;
            _userManager = userManager;
            //_emailService = emailService;
            //_context = context;
            //_config = config;
            //_facebookHttpClient = new HttpClient
            //{
            //    BaseAddress = new Uri("https://graph.facebook.com")
            //};
        }

        [Authorize]
        [HttpGet("refresh-user-token")]
        public async Task<ActionResult<UserDto>> RefereshUserToken()
        {

            var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);
                
                return CreateApplicationUserDto(user);
        
        }

        //[Authorize]
        //[HttpPost("refresh-token")]
        //public async Task<ActionResult<UserDto>> RefereshToken()
        //{
        //    var token = Request.Cookies["identityAppRefreshToken"];
        //    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        //    if (IsValidRefreshTokenAsync(userId, token).GetAwaiter().GetResult())
        //    {
        //        var user = await _userManager.FindByIdAsync(userId);
        //        if (user == null) return Unauthorized("Invalid or expired token, please try to login");
        //        return await CreateApplicationUserDto(user);
        //    }

        //    return Unauthorized("Invalid or expired token, please try to login");
        //}

        //[Authorize]
        //[HttpGet("refresh-page")]
        //public async Task<ActionResult<UserDto>> RefreshPage()
        //{
        //    var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);

        //    if (await _userManager.IsLockedOutAsync(user))
        //    {
        //        return Unauthorized("You have been locked out");
        //    }
        //    return await CreateApplicationUserDto(user);
        //}   

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null) return Unauthorized("Invalid username or password");

            if (user.EmailConfirmed == false) return Unauthorized("Please confirm your email.");

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if(!result.Succeeded) return Unauthorized("Invalid username or password");

            return CreateApplicationUserDto(user);

            //if (result.IsLockedOut)
            //{
            //    return Unauthorized(string.Format("Your account has been locked. You should wait until {0} (UTC time) to be able to login", user.LockoutEnd));
            //}

            //if (!result.Succeeded)
            //{
            //    // User has input an invalid password
            //    if (!user.UserName.Equals(SD.AdminUserName))
            //    {
            //        // Increamenting AccessFailedCount of the AspNetUser by 1
            //        await _userManager.AccessFailedAsync(user);
            //    }

            //    if (user.AccessFailedCount >= SD.MaximumLoginAttempts)
            //    {
            //        // Lock the user for one day
            //        await _userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddDays(1));
            //        return Unauthorized(string.Format("Your account has been locked. You should wait until {0} (UTC time) to be able to login", user.LockoutEnd));
            //    }


            //    return Unauthorized("Invalid username or password");
            //}

            //await _userManager.ResetAccessFailedCountAsync(user);
            //await _userManager.SetLockoutEndDateAsync(user, null);

            //return await CreateApplicationUserDto(user);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto model)
        {
            if (await CheckEmailExistsAsync(model.Email))
            {
                return BadRequest($"An existing account is using {model.Email}, email addres. Please try with another email address");
            }

            var userToAdd = new User
            {
                FirstName = model.FirstName.ToLower(),
                LastName = model.LastName.ToLower(),
                UserName = model.Email.ToLower(),
                Email = model.Email.ToLower(),
                EmailConfirmed = true
            };

            // creates a user inside our AspNetUsers table inside our database
            var result = await _userManager.CreateAsync(userToAdd, model.Password);
            if (!result.Succeeded) return BadRequest(result.Errors);

            return Ok("Your account has been created, you can login");

            //await _userManager.AddToRoleAsync(userToAdd, SD.PlayerRole);

            //try
            //{
            //    if (await SendConfirmEMailAsync(userToAdd))
            //    {
            //        return Ok(new JsonResult(new { title = "Account Created", message = "Your account has been created, please confrim your email address" }));
            //    }

            //    return BadRequest("Failed to send email. Please contact admin");
            //}
            //catch (Exception)
            //{
            //    return BadRequest("Failed to send email. Please contact admin");
            //}

        }

        #region Private Helper Methods
        //private async Task<UserDto> CreateApplicationUserDto(User user)
        private UserDto CreateApplicationUserDto(User user)
        {
            //await SaveRefreshTokenAsync(user);
            return new UserDto
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                //JWT = await _jwtService.CreateJWT(user),
                JWT = _jwtService.CreateJWT(user),
            };
        }

        private async Task<bool> CheckEmailExistsAsync(string email)
        {
            return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
        }   

        #endregion
    }
}
