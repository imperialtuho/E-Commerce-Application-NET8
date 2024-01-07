using Application.Configurations.Commands;
using Domain.Common;
using System.ComponentModel.DataAnnotations;

namespace Application.Configurations.Security.Commands.Login
{
    public class LoginCommand : CommandBase<BaseResponseObject>
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        public LoginCommand(string userName, string password, string email)
        {
            UserName = userName;
            Password = password;
            Email = email;
        }
    }
}