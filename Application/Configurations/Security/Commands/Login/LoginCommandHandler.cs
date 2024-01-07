using Application.Configurations.Commands;
using Application.Configurations.Interfaces.Services;
using Application.Dtos.Identity;
using Domain.Common;
using Microsoft.Extensions.Logging;

namespace Application.Configurations.Security.Commands.Login
{
    public class LoginCommandHandler : ICommandHandler<LoginCommand, BaseResponseObject>
    {
        private readonly ILogger<LoginCommandHandler> _logger;
        private readonly IAuthService _authService;

        public LoginCommandHandler(ILogger<LoginCommandHandler> logger, IAuthService authService)
        {
            _logger = logger;
            _authService = authService;
        }

        public async Task<BaseResponseObject> Handle(LoginCommand request, CancellationToken cancellationToken)
        {
            _logger.LogInformation($"Call {nameof(LoginCommandHandler)}.");

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
                TokenDto token = await _authService.LoginAsync(request.Email, request.Password);

                if (token != null)
                {
                    result.Message = ResponseMessage.Success;
                    result.Data = token;
                    result.Status = true;
                    result.StatusCode = HttpStatusCode.OK;

                    return result;
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"{nameof(LoginCommandHandler)} failed");

                return result;
            }
        }
    }
}