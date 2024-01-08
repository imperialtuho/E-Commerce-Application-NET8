using Application.Common.CqrsBase.Commands;
using Application.Configurations.Interfaces.Services;
using Application.Dtos.Identity;
using Domain.Common;

namespace Application.Configurations.Security.Commands.Token
{
    public class TokenCommandHandler : ICommandHandler<TokenCommand, BaseResponseObject>
    {
        private readonly IAuthService _authService;

        public TokenCommandHandler(IAuthService authService)
        {
            _authService = authService;
        }

        async Task<BaseResponseObject> IRequestHandler<TokenCommand, BaseResponseObject>.Handle(TokenCommand request, CancellationToken cancellationToken)
        {
            var result = new BaseResponseObject()
            {
                CorrelationId = Guid.NewGuid(),
                Message = ResponseMessage.Failed,
                StatusCode = HttpStatusCode.InternalServerError
            };

            try
            {
                var tokenDto = new TokenDto()
                {
                    Token = request.Token,
                    RefreshToken = request.RefreshToken,
                };

                TokenDto? refreshToken = await _authService.RefreshTokenAsync(tokenDto);

                if (refreshToken != null)
                {
                    result.Message = ResponseMessage.Success;
                    result.Data = refreshToken;
                    result.StatusCode = HttpStatusCode.OK;
                    result.Status = true;

                    return result;
                }

                result.Message = ResponseMessage.UnknownError;

                return result;
            }
            catch (Exception ex)
            {
                return result;
            }
        }
    }
}