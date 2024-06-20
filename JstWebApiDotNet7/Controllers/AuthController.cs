using BCrypt.Net;
using JstWebApiDotNet7.Models;
using JstWebApiDotNet7.Models.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JstWebApiDotNet7.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static User user = new User();

        private readonly IConfiguration configuration;
        public AuthController(IConfiguration configuration)
        {

            this.configuration = configuration;

        }

        [HttpPost("register")]
        public  ActionResult<User> Register(UserDTO model)
        {
            string hashPassword= BCrypt.Net.BCrypt.HashPassword(model.Password);

            user.userName = model.UserName;
            user.password = hashPassword;

            return Ok(user);
        }


        [HttpPost("login")]
        public ActionResult<User> Login(UserDTO model)
        {
            if(user.userName!= model.UserName)
            {
                return BadRequest("User not exist");
            }

            if(!BCrypt.Net.BCrypt.Verify(model.Password, user.password))
            {
                return BadRequest("Invalid user name or password");
            }

            var token = CreateToken(user);
            return Ok(token);
        }


        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.userName),
                new Claim(ClaimTypes.Role, "admin"),
                new Claim(ClaimTypes.Role, "user") 
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.
                GetBytes(configuration.GetSection("AppSettings:SecretToken").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                    claims:claims,
                    expires:DateTime.Now.AddDays(1),
                    signingCredentials: creds
                );

            var jwt=new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
