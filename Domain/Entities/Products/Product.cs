using Domain.Common;

namespace Domain.Entities.Products
{
    public class Product : BaseEntity<int>
    {
        public string Name { get; set; }

        public string Description { get; set; }
    }
}