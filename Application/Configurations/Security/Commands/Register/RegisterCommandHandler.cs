using Application.Common.CqrsBase.Commands;
using Application.Configurations.Interfaces.Services;
using Application.Configurations.Security.Commands.Login;
using Application.Dtos.Identity;
using Domain.Common;
using Microsoft.Extensions.Logging;

namespace Application.Configurations.Security.Commands.Register
{
    public class RegisterCommandHandler : ICommandHandler<RegisterCommand, BaseResponseObject>
    {
        private readonly ILogger<LoginCommandHandler> _logger;
        private readonly IAuthService _authService;

        public RegisterCommandHandler(ILogger<LoginCommandHandler> logger, IAuthService authService)
        {
            _logger = logger;
            _authService = authService;
        }

        public async Task<BaseResponseObject> Handle(RegisterCommand request, CancellationToken cancellationToken)
        {
            var user = new UserDto
            {
                Email = request.Email,
                UserName = request.UserName
            };

            var result = new BaseResponseObject
            {
                CorrelationId = Guid.NewGuid(),
                Message = ResponseMessage.UnknownError,
                Data = null,
                Status = false,
                StatusCode = HttpStatusCode.InternalServerError
            };

            try
            {
                TokenDto token = await _authService.RegisterAsync(user, request.Password, request.Roles, request.Claims);

                if (token != null)
                {
                    result.Message = "Register successfully!";
                    result.Data = token;
                    result.Status = true;
                    result.StatusCode = HttpStatusCode.OK;

                    return result;
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Call to {nameof(RegisterCommandHandler)} failed");
                return result;
            }
        }
    }
}