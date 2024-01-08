using Domain.Common;
using Domain.Entities.Categories;

namespace Domain.Entities.RelationalEntity
{
    public class ProductCategories : BaseEntity<int>
    {
        public int CategoryId { get; set; }

        public int ProductId { get; set; }

        public virtual Product Product { get; set; }

        public virtual Category Category { get; set; }
    }
}