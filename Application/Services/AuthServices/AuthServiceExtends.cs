using Application.Dtos.Identity;
using Domain.Entities.Identity;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace Application.Services
{
    public partial class AuthService
    {
        private const int NAME_LENGTH = 3;

        private async Task<IEnumerable<string>> InsertRoleAsync(IList<string> roles)
        {
            try
            {
                var rolesList = new List<string>();

                foreach (string role in roles)
                {
                    if (await _roleManager.RoleExistsAsync(role))
                    {
                        continue;
                    }

                    rolesList.Add(role);
                    await _roleManager.CreateAsync(new IdentityRole(role));
                }

                return rolesList;
            }
            catch (Exception ex)
            {
                return new List<string>();
            }
        }

        private void ValidateRoles(IList<string>? roles)
        {
            var allRoles = _roleManager.Roles.Select(r => r.Name).ToList();

            if (roles != null && roles.Any(r => !allRoles.Contains(r)))
            {
                throw new ArgumentException($"Roles must belong to this list: {string.Join(", ", allRoles)}.");
            }
        }

        private void ValidateClaims(IList<ClaimDto> claims)
        {
            if (claims != null && claims.Any(c => string.IsNullOrEmpty(c.Type) || string.IsNullOrEmpty(c.Value)))
            {
                throw new ArgumentException($"Claim type and value must not be empty.");
            }
        }

        private void ValidateUser(UserDto user, string password)
        {
            ArgumentNullException.ThrowIfNull(user);

            ValidateEmail(user.Email);
            ValidateUserName(user.UserName);
            ValidatePassword(password);
        }

        private void ValidateUserName(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("Name is required.");
            }

            if (name.Length < NAME_LENGTH)
            {
                throw new ArgumentException($"Name must have at least {NAME_LENGTH} characters.");
            }
        }

        private void ValidateEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                throw new ArgumentException("Email is required.");
            }

            var emailPattern = @"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$";

            if (!Regex.IsMatch(email, emailPattern))
            {
                throw new ArgumentException("Invalid email.");
            }
        }

        private void ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is required.");
            }

            var passwordPattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$";

            if (!Regex.IsMatch(password, passwordPattern))
            {
                throw new ArgumentException("Password must have at least 8 characters, " +
                    "at least 1 uppercase letter, at least 1 lowercase letter, " +
                    "at least 1 digit and at least 1 special character.");
            }
        }

        private async Task AddRoles(ApplicationUser user, IList<string> roles)
        {
            var addRolesResult = await _userManager.AddToRolesAsync(user, roles);

            if (!addRolesResult.Succeeded)
            {
                throw new InvalidDataException("Add roles failed.");
            }
        }

        private async Task AddClaims(ApplicationUser user, IList<ClaimDto> claimsInput)
        {
            var claims = claimsInput.Select(c => new Claim(c.Type, c.Value));

            var addClaimsResult = await _userManager.AddClaimsAsync(user, claims);

            if (!addClaimsResult.Succeeded)
            {
                throw new InvalidDataException("Add claims failed.");
            }
        }

        private UserDto GetUserDto(ApplicationUser from)
        {
            return new UserDto
            {
                Id = from.Id,
                UserName = from.UserName,
                Email = from.Email
            };
        }

        private IList<UserDto> GetUserDtos(List<ApplicationUser> from)
        {
            return from.Select(u => new UserDto
            {
                Id = u.Id,
                UserName = u.UserName,
                Email = u.Email
            }).ToList();
        }
    }
}