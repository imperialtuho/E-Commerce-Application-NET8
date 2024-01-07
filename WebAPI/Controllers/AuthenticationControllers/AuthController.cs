using Application.Configurations.Security.Commands.Login;
using Application.Configurations.Security.Commands.Register;
using Application.Configurations.Security.Commands.Role;
using Application.Configurations.Security.Commands.Token;
using Domain.Common;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers.AuthenticationControllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IMediator _mediator;

        public AuthController(IMediator mediator)
        {
            _mediator = mediator;
        }

        /// <summary>
        /// Login.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns>System.Task{BaseResponseObject}.</returns>
        [HttpPost]
        [Route("login")]
        public async Task<BaseResponseObject> Login([FromBody] LoginCommand model)
        {
            return await _mediator.Send(new LoginCommand(model.UserName, model.Password, model.Email));
        }

        /// <summary>
        /// Registers user.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns>System.Task{BaseResponseObject}.</returns>
        [HttpPost]
        [Route("register")]
        public async Task<BaseResponseObject> Register([FromBody] RegisterCommand model)
        {
            return await _mediator.Send(new RegisterCommand(model.UserName, model.Password, model.Email, model.Roles, model.Claims));
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<BaseResponseObject> RefreshTokenAsync([FromBody] TokenCommand token)
        {
            return await _mediator.Send(new TokenCommand(token.Token, token.RefreshToken));
        }

        [HttpPost]
        [Route("role")]
        [Authorize(Roles ="SuperAdmin")]
        public async Task<BaseResponseObject> AddRoleAsync([FromBody] RoleCommand request)
        {
            return await _mediator.Send(new RoleCommand(request.Roles));
        }
    }
}