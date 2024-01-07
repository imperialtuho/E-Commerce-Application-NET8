using Application.Dtos.Identity;

namespace Application.Configurations.Interfaces.Services
{
    public interface IAuthService
    {
        Task<UserDto> GetByIdAsync(string id);

        Task<UserDto> GetByEmailAsync(string email);

        IList<UserDto> GetAll();

        Task<TokenDto> RegisterAsync(UserDto user, string password, IList<string>? roles = null, IList<ClaimDto>? claims = null);

        Task<bool> AddUserToRolesAsync(string email, IList<string> roles);

        Task<bool> AddClaimAsync(string email, string claimType, string claimValue);

        Task<TokenDto> LoginAsync(string email, string password);

        Task<TokenDto> RefreshTokenAsync(TokenDto token);

        Task<bool> UpdatePasswordAsync(string id, string newPass);

        Task<bool> DeleteAsync(string id);

        Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth);

        Task<bool> LoginWith2FaAsync(string email, string password);

        Task<string> Get2FaTokenAsync(string email);

        Task<TokenDto> Verify2FaTokenAsync(string email, string code);

        Task<bool> RegisterWithEmailConfirmAsync(UserDto user, string password, IList<string>? roles = null, IList<ClaimDto>? claims = null);

        Task<bool> ResendVerificationEmail(string email);

        Task<TokenDto> VerifyEmailTokenAsync(string email, string token);

        Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password);

        Task<bool> SendResetPasswordEmailAsync(string email);

        Task<bool> ResetPasswordAsync(string email, string password, string token);

        Task<bool> InvalidateUserTokens(string email);

        Task<IEnumerable<string>> AddRoleAsync(IList<string> roles);
    }
}