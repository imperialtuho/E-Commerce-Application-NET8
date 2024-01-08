using Application.Configurations.Interfaces.Repositories;
using Application.Configurations.Interfaces.Services;
using Application.Dtos.Identity;
using Ardalis.GuardClauses;
using Domain.Entities.Identity;
using Domain.Enums;
using Domain.Helpers;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Application.Services
{
    public partial class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        private readonly RoleManager<IdentityRole> _roleManager;

        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;

        private readonly ITokenRepository _tokenRepository;

        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public AuthService(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IPasswordHasher<ApplicationUser> passwordHasher,
            ITokenRepository tokenRepository,
            IRefreshTokenRepository refreshTokenRepository)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _passwordHasher = passwordHasher;
            _tokenRepository = tokenRepository;
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task<bool> AddClaimAsync(string email, string claimType, string claimValue)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var claim = new Claim(claimType, claimValue);

                IdentityResult result = await _userManager.AddClaimAsync(user, claim);

                if (result.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new ArgumentException("User doesn't exists.");
        }

        public async Task<bool> AddUserToRolesAsync(string email, IList<string> roles)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                ValidateRoles(roles);

                IdentityResult result = await _userManager.AddToRolesAsync(user, roles);

                if (result.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new ArgumentException("User doesn't exists.");
        }

        public async Task<bool> DeleteAsync(string id)
        {
            ApplicationUser? currentUser = await _userManager.FindByIdAsync(id);

            if (currentUser != null)
            {
                IdentityResult rs = await _userManager.DeleteAsync(currentUser);

                if (rs.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new NotFoundException(id, "User");
        }

        public async Task<string> Get2FaTokenAsync(string email)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                string token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultProvider);

                if (!string.IsNullOrEmpty(token))
                {
                    var emailHelper = new EmailHelper();
                    _ = emailHelper.SendEmailTwoFactorCode(user.Email, token);

                    return token;
                }

                throw new ApplicationException("Something went wrong.");
            }

            throw new ArgumentException("User doesn't exist.");
        }

        public IList<UserDto> GetAll()
        {
            return GetUserDtos(_userManager.Users.ToList());
        }

        public async Task<UserDto> GetByEmailAsync(string email)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                return GetUserDto(user);
            }

            throw new NotFoundException(email, "User");
        }

        public async Task<UserDto> GetByIdAsync(string id)
        {
            ApplicationUser? user = await _userManager.FindByIdAsync(id);

            if (user != null)
            {
                return GetUserDto(user);
            }

            throw new NotFoundException(id, "User");
        }

        public async Task<bool> InvalidateUserTokens(string email)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                await _refreshTokenRepository.InvalidateUserTokens(user.Id);
                await _refreshTokenRepository.CompleteAsync();

                return true;
            }

            throw new ArgumentException("User doesn't exist.");
        }

        public async Task<TokenDto> LoginAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.");
            }

            ApplicationUser? loginUser = await _userManager.FindByEmailAsync(email);

            if (loginUser != null)
            {
                bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

                if (isPasswordMatched)
                {
                    IList<string> roles = await _userManager.GetRolesAsync(loginUser);
                    IList<Claim> claims = await _userManager.GetClaimsAsync(loginUser);

                    return await _tokenRepository.CreateTokenAsync(GetUserDto(loginUser), roles, claims);
                }
            }

            throw new ArgumentException($"Invalid credential.");
        }

        public async Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.");
            }

            ApplicationUser? loginUser = await _userManager.FindByEmailAsync(email);

            if (loginUser != null)
            {
                bool isEmailConfirmed = loginUser.EmailConfirmed;

                if (isEmailConfirmed)
                {
                    bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

                    if (isPasswordMatched)
                    {
                        IList<string> roles = await _userManager.GetRolesAsync(loginUser);
                        IList<Claim> claims = await _userManager.GetClaimsAsync(loginUser);

                        return await _tokenRepository.CreateTokenAsync(GetUserDto(loginUser), roles, claims);
                    }

                    throw new ArgumentException($"Invalid credential.");
                }

                throw new ArgumentException($"User have not been verified.");
            }

            throw new ArgumentException($"Invalid credential.");
        }

        public async Task<bool> LoginWith2FaAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.");
            }

            ApplicationUser? loginUser = await _userManager.FindByEmailAsync(email);

            if (loginUser != null)
            {
                bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

                if (isPasswordMatched)
                {
                    string token = await _userManager.GenerateTwoFactorTokenAsync(loginUser, TokenOptions.DefaultProvider);

                    if (!string.IsNullOrEmpty(token))
                    {
                        var emailHelper = new EmailHelper();
                        bool emailResponse = emailHelper.SendEmailTwoFactorCode(loginUser.Email, token);

                        return emailResponse;
                    }

                    throw new ApplicationException("Something went wrong.");
                }
            }

            throw new ArgumentException($"Invalid credential.");
        }

        public async Task<TokenDto> RefreshTokenAsync(TokenDto token)
        {
            ClaimsPrincipal? principal = _tokenRepository.GetPrincipalFromExpiredToken(token.Token);

            if (principal != null)
            {
                long tokenExpiryUnix = long.Parse(principal.Claims.Single(p => p.Type == JwtRegisteredClaimNames.Exp).Value);
                DateTime tokenExpiryDate = DateTime.UnixEpoch.AddSeconds(tokenExpiryUnix);

                if (tokenExpiryDate <= DateTime.Now)
                {
                    string jti = principal.Claims.Single(p => p.Type == JwtRegisteredClaimNames.Jti).Value;
                    RefreshToken? storedRefreshToken = await _refreshTokenRepository.FindByTokenAsync(token.RefreshToken);

                    if (
                        storedRefreshToken != null &&
                        storedRefreshToken.JwtId == jti &&
                        storedRefreshToken.ExpiryDate >= DateTime.Now &&
                        !storedRefreshToken.Invalidated &&
                        !storedRefreshToken.Used)
                    {
                        storedRefreshToken.Used = true;
                        _refreshTokenRepository.Update(storedRefreshToken);
                        await _refreshTokenRepository.CompleteAsync();

                        string? email = principal.Claims.Single(p => p.Type == ClaimTypes.Email).Value;
                        ApplicationUser? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException(email, email);
                        IList<string> roles = await _userManager.GetRolesAsync(user);

                        TokenDto resource = await _tokenRepository.CreateTokenAsync(GetUserDto(user), roles);
                        return resource;
                    }

                    throw new ArgumentException("Invalid refresh token.");
                }

                throw new ArgumentException("The access token has not expired yet.");
            }

            throw new ArgumentException("Invalid token.");
        }

        public async Task<TokenDto> RegisterAsync(UserDto user, string password, IList<ClaimDto> claims, IList<string>? roles = null)
        {
            ApplicationUser? foundUserByEmail = await _userManager.FindByEmailAsync(user.Email);
            ApplicationUser? foundUserByUserName = await _userManager.FindByNameAsync(user.UserName);

            if (foundUserByEmail == null && foundUserByUserName == null)
            {
                var appUser = new ApplicationUser
                {
                    UserName = user.UserName,
                    Email = user.Email
                };

                ValidateUser(user, password);
                ValidateRoles(roles);
                ValidateClaims(claims);

                IdentityResult rs = await _userManager.CreateAsync(appUser, password);

                if (rs.Succeeded)
                {
                    ApplicationUser? newUser = await _userManager.FindByEmailAsync(user.Email) ?? throw new NotFoundException(user.Email, user.Email);
                    var addingRoles = roles != null && roles.Any() ? roles : new List<string>() { Roles.Member.ToString() };
                    await AddRoles(newUser, addingRoles);
                    await AddClaims(newUser, claims);
                    var addedClaims = await _userManager.GetClaimsAsync(newUser);

                    return await _tokenRepository.CreateTokenAsync(GetUserDto(newUser), addingRoles, addedClaims);
                }

                throw new InvalidOperationException(ResponseMessage.UnknownError);
            }

            throw new ArgumentException("User with email exists, please try another email.");
        }

        public async Task<bool> RegisterWithEmailConfirmAsync(UserDto user, string password, IList<ClaimDto>? claims, IList<string>? roles = null)
        {
            ApplicationUser? foundUserByEmail = await _userManager.FindByEmailAsync(user.Email);
            ApplicationUser? foundUserByUserName = await _userManager.FindByNameAsync(user.UserName);

            if (foundUserByEmail == null && foundUserByUserName == null)
            {
                var appUser = new ApplicationUser
                {
                    UserName = user.UserName,
                    Email = user.Email
                };

                ValidateUser(user, password);
                ValidateRoles(roles);
                ValidateClaims(claims);

                IdentityResult? rs = await _userManager.CreateAsync(appUser, password);

                if (rs.Succeeded)
                {
                    ApplicationUser? newUser = await _userManager.FindByEmailAsync(user.Email) ?? throw new NotFoundException(user.Email, user.Email);
                    var addingRoles = roles != null && roles.Any() ? roles : new List<string>() { Roles.Member.ToString() };
                    await AddRoles(newUser, addingRoles);
                    await AddClaims(newUser, claims);

                    string token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

                    if (!string.IsNullOrEmpty(token))
                    {
                        var emailHelper = new EmailHelper();
                        bool emailResponse = emailHelper.SendEmailTwoFactorCode(user.Email, token);

                        return emailResponse;
                    }
                }

                throw new ApplicationException("Something went wrong.");
            }

            throw new ArgumentException("User with email exists, please try another email.");
        }

        public async Task<bool> ResendVerificationEmail(string email)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                string? token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                if (token != null)
                {
                    var emailHelper = new EmailHelper();
                    bool emailResponse = emailHelper.SendEmailTwoFactorCode(user.Email, token);

                    return emailResponse;
                }

                return false;
            }

            throw new ArgumentException("User doesn't exist.");
        }

        public async Task<bool> ResetPasswordAsync(string email, string password, string token)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                ValidatePassword(password);

                IdentityResult? result = await _userManager.ResetPasswordAsync(user, token, password);

                if (result.Succeeded)
                {
                    return true;
                }

                throw new ArgumentException("Reset password failed, please try again.");
            }

            throw new ArgumentException("User doesn't exist.");
        }

        public async Task<bool> SendResetPasswordEmailAsync(string email)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                string token = await _userManager.GeneratePasswordResetTokenAsync(user);

                if (token != null)
                {
                    var emailHelper = new EmailHelper();
                    bool emailResponse = emailHelper.SendEmailTwoFactorCode(user.Email, token);

                    return emailResponse;
                }

                return false;
            }

            throw new ArgumentException("User doesn't exist.");
        }

        public async Task<bool> UpdatePasswordAsync(string id, string newPass)
        {
            ApplicationUser? currentUser = await _userManager.FindByIdAsync(id);

            if (currentUser != null)
            {
                ValidatePassword(newPass);

                currentUser.PasswordHash = _passwordHasher.HashPassword(currentUser, newPass);

                IdentityResult? user = await _userManager.UpdateAsync(currentUser);

                if (user.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new NotFoundException(id, nameof(UpdatePasswordAsync));
        }

        public async Task<TokenDto> Verify2FaTokenAsync(string email, string token)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException(email, email);

            bool verified = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultProvider, token);

            if (verified)
            {
                IList<string> roles = await _userManager.GetRolesAsync(user);
                IList<Claim> claims = await _userManager.GetClaimsAsync(user);

                return await _tokenRepository.CreateTokenAsync(GetUserDto(user), roles, claims);
            }

            throw new ArgumentException("OTP does not match, please try again.");
        }

        public async Task<TokenDto> VerifyEmailTokenAsync(string email, string token)
        {
            ApplicationUser? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException(email, email);

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                IList<string> roles = await _userManager.GetRolesAsync(user);
                IList<Claim> claims = await _userManager.GetClaimsAsync(user);

                return await _tokenRepository.CreateTokenAsync(GetUserDto(user), roles, claims);
            }

            throw new ArgumentException("Email verification failed, please try again.");
        }

        public async Task<IEnumerable<string>> AddRoleAsync(IList<string> roles)
        {
            return await InsertRoleAsync(roles);
        }

        public Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth)
        {
            throw new NotImplementedException();
        }
    }
}