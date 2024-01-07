using System.Net;

namespace Domain.Common
{
    public class BaseResponseObject
    {
        public Guid CorrelationId { get; set; }

        public string? Message { get; set; }

        public object? Data { get; set; }

        public bool Status { get; set; }

        public HttpStatusCode StatusCode { get; set; }
    }
}