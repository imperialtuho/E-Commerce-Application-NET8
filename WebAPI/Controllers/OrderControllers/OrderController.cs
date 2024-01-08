using Domain.Common;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers.OrderControllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public class OrderController : ControllerBase
    {
        private readonly IMediator _mediator;

        /// <summary>
        /// Order controller constructor.
        /// </summary>
        /// <param name="mediator">The mediator.</param>
        public OrderController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpPost]
        [Route("{id}")]
        public async Task<ActionResult<BaseResponseObject>> GetByIdAsync(int id)
        {
            return Ok(id);
        }
    }
}