using Application.Common.CqrsBase.Commands;
using Domain.Common;

namespace Application.Configurations.Security.Commands.Token
{
    public class TokenCommand : CommandBase<BaseResponseObject>
    {
        public string Token { get; set; }

        public string RefreshToken { get; set; }

        public TokenCommand(string token, string refreshToken)
        {
            Token = token;
            RefreshToken = refreshToken;
        }
    }
}