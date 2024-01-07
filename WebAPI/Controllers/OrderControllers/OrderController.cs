using Domain.Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers.OrderControllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public class OrderController : ControllerBase
    {
        [HttpPost]
        [Route("{id}")]
        public async Task<ActionResult<BaseResponseObject>> GetOrderByIdAsync(int id)
        {
            return Ok(id);
        }
    }
}