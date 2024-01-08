using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers.ProductControllers
{
    [ApiController]
    [Route("[controller]")]
    public class ProductController : ControllerBase
    {
        private readonly IMediator _mediator;

        /// <summary>
        /// Product controller constructor.
        /// </summary>
        /// <param name="mediator">The mediator.</param>
        public ProductController(IMediator mediator)
        {
            _mediator = mediator;
        }
    }
}