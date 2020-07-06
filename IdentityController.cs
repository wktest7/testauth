using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Nowa.Infrastructure.Services;

namespace Nowa.Api.Controllers
{
    [Route("api/[controller]")]
    public class IdentityController : ControllerBase
    {
        private readonly IIdentityService identityService;
        public IdentityController(IIdentityService identityService)
        {
            this.identityService = identityService;
        }

        [HttpPost("register")]
        public async Task<IActionResult > Register([FromBody] UserRegistrationRequest request)
        {
            var authResponse = await identityService.RegisterAsync(request.Email, request.Password);
            return Ok(authResponse);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserRegistrationRequest request)
        {
            var authResponse = await identityService.LoginAsync(request.Email, request.Password);
            return Ok(authResponse);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromQuery] string jwtToken)
        {
            var authResponse = await identityService.RefreshTokenAsync(jwtToken);
            return Ok(authResponse);
        }

        [Authorize]
        [HttpGet("getValues")]
        public async Task<IActionResult> GetValues()
        {

            return Ok("afdsfsd fds fsdf dsf sdf sd");
        }



    }
}
