using MediatR;

namespace WebAPI.Controllers.CartControllers
{
    public class CartController
    {
        private readonly IMediator _mediator;

        /// <summary>
        /// Cart controller constructor.
        /// </summary>
        /// <param name="mediator">The mediator.</param>
        public CartController(IMediator mediator)
        {
            _mediator = mediator;
        }
    }
}