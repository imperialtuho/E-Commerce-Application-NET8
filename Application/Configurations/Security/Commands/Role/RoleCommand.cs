using Application.Configurations.Commands;
using Domain.Common;

namespace Application.Configurations.Security.Commands.Role
{
    public class RoleCommand : CommandBase<BaseResponseObject>
    {
        public RoleCommand(IList<string> roles)
        {
            Roles = roles;
        }

        public IList<string> Roles { get; set; }
    }
}