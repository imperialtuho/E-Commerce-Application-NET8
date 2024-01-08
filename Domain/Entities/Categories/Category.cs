using Domain.Common;
using Domain.Entities.RelationalEntity;

namespace Domain.Entities.Categories
{
    public class Category : BaseEntity<int>
    {
        public required string Name { get; set; }

        public string? Description { get; set; }

        public virtual ICollection<ProductCategories> ProductCategories { get; set; } = new HashSet<ProductCategories>();
    }
}