using Application.Configurations.Commands;
using Application.Configurations.Interfaces.Services;
using Domain.Common;
using Domain.Constants;

namespace Application.Configurations.Security.Commands.Role
{
    public class RoleCommandHandler : ICommandHandler<RoleCommand, BaseResponseObject>
    {
        private readonly IAuthService _authService;

        public RoleCommandHandler(IAuthService authService)
        {
            _authService = authService;
        }

        public async Task<BaseResponseObject> Handle(RoleCommand request, CancellationToken cancellationToken)
        {
            var response = new BaseResponseObject
            {
                CorrelationId = Guid.NewGuid(),
                Data = null,
                Message = ResponseMessage.Failed,
                Status = false,
                StatusCode = HttpStatusCode.InternalServerError
            };

            IEnumerable<string> roleResult = await _authService.AddRoleAsync(request.Roles);

            if (roleResult != null && roleResult.Any())
            {
                response.Data = roleResult;
                response.Message = ResponseMessage.Success;
                response.Status = true;
                response.StatusCode = HttpStatusCode.OK;

                return response;
            }

            return response;
        }
    }
}