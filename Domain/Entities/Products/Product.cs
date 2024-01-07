using Domain.Common;

namespace Domain.Entities.Products
{
    public class Product : BaseEntity<int>
    {
        public string ProductName { get; set; }

        public string Description { get; set; }
    }
}