using System.Net;
using System.Net.Mail;

namespace Domain.Helpers
{
    public class EmailHelper
    {
        public bool SendEmailTwoFactorCode(string userEmail, string code)
        {
            MailMessage mailMessage = new MailMessage();
            mailMessage.From = new MailAddress("admin@test.com");
            mailMessage.To.Add(new MailAddress(userEmail));

            mailMessage.Subject = "Two Factor Code";
            mailMessage.IsBodyHtml = true;
            mailMessage.Body = code;

            var client = new SmtpClient("sandbox.smtp.mailtrap.io", 2525)
            {
                Credentials = new NetworkCredential("b3763ec6ff4b9d", "0e581a05dbec85"),
                EnableSsl = true
            };
            client.Credentials = new NetworkCredential("b3763ec6ff4b9d", "0e581a05dbec85");

            try
            {
                client.Send(mailMessage);
                return true;
            }
            catch (Exception ex)
            {
                // log exception
            }
            return false;
        }
    }
}
