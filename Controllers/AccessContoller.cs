using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtTokenLearn.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccessContoller : ControllerBase
    {
        // Общий доступ (без токена)
        [HttpGet("public")]
        public IActionResult GetPublic()
        {
            return Ok("Это общедоступная информация. Токен не нужен.");
        }

        // Для авторизированных пользователей (неважна роль)
        [HttpGet("user-only")]
        [Authorize]
        public IActionResult GetUserOnly()
        {
            // имя пользователя прямо из токена
            var userName = User.Identity?.Name;
            return Ok($"Привет, {userName}! Ты авторизован и видишь этот текст.");
        }

        // Только для Админа
        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAdminOnly()
        {
            return Ok("Привет, Босс! Если ты это видишь, значит у тебя роль Admin.");
        }
    }
}
