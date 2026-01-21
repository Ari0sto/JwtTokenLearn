using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtTokenLearn.Data;
using JwtTokenLearn.Models;

namespace JwtTokenLearn.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;

        // Внедрение UserManager (для работы с БД) и Configuration (для чтения ключа из appsettings)
        public AccountController(UserManager<AppUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        // 1) Registration
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            var user = new AppUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // При регистрации роль User по умолчанию
                await _userManager.AddToRoleAsync(user, "User");
                return Ok(new { message = "Пользователь успешно зарегистрирован" });
            }

            return BadRequest(result.Errors);
        }

        // 2) Login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            // Проверки: существует ли пользователь
            // Правильный ли пароль
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                // Если да - генерация токена
                var token = await GenerateJwtToken(user);
                return Ok(new { token });
            }

            return Unauthorized(new { message = "Неверный логин или пароль" });
        }

        // 3) Method Gen. Token'a
        private async Task<string> GenerateJwtToken(AppUser user)
        {
            var jwtSettings = _configuration.GetSection("Jwt");
            var key = Encoding.ASCII.GetBytes(jwtSettings["Key"]);

            // Получаем роли (Admin, User и т.д.)
            var userRoles = await _userManager.GetRolesAsync(user);

            // Создаем список "Заявлений" (Claims) то что мы зашьем в токен
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id), // ID пользователя
                new Claim(JwtRegisteredClaimNames.Email, user.Email), // Email
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Уникальный ID токена
            };

            // Добавление ролей в Claims
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Созд. описание токена
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(15), // Время жизни 15 минут
                Issuer = jwtSettings["Issuer"],
                Audience = jwtSettings["Audience"],
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature) // Подпись
            };

            // Gen. token
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
