using Microsoft.AspNetCore.Identity;
namespace JwtTokenLearn.Data
{
    public static class DbInitializer
    {
        public static async Task SeedAsync(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            // 1. Create Roles
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new IdentityRole("Admin"));
            }

            if (!await roleManager.RoleExistsAsync("User"))
            {
                await roleManager.CreateAsync(new IdentityRole("User"));
            }

            // 2. Create Admin
            if (await userManager.FindByEmailAsync("admin@test.com") == null)
            {
                var admin = new AppUser
                {
                    UserName = "admin@test.com",
                    Email = "admin@test.com",
                    EmailConfirmed = true
                };

                // 3. Create User with password
                var result = await userManager.CreateAsync(admin, "Admin@123");

                if (result.Succeeded)
                {
                    // Выдаем роль Админа
                    await userManager.AddToRoleAsync(admin, "Admin");
                }
            }
        }
    }
}
