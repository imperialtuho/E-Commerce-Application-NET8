using Application.Configurations.Commands;
using Application.Dtos.Identity;
using Domain.Common;
using System.ComponentModel.DataAnnotations;

namespace Application.Configurations.Security.Commands.Register
{
    public class RegisterCommand : CommandBase<BaseResponseObject>
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }

        [Required]
        public string Email { get; set; }

        public IList<string>? Roles { get; set; }

        public IList<ClaimDto> Claims { get; set; }

        public RegisterCommand(string userName, string password, string email, IList<string>? roles, IList<ClaimDto> claims)
        {
            UserName = userName;
            Password = password;
            Email = email;
            Roles = roles;
            Claims = claims;
        }
    }
}