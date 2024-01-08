using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers.StoreControllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class StoreController : ControllerBase
    {
        private readonly IMediator _mediator;

        /// <summary>
        /// Store controller constructor.
        /// </summary>
        /// <param name="mediator">The mediator.</param>
        public StoreController(IMediator mediator)
        {
            _mediator = mediator;
        }
    }
}