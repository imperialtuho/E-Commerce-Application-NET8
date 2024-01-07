namespace Application.Dtos.Identity
{
    public class ExternalAuthDto
    {
        public string? Provider { get; set; }

        public string? IdToken { get; set; }
    }
}