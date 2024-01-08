using Domain.Common;

namespace Domain.Entities.RelationalEntities
{
    public class ProductAttributes : BaseEntity<int>
    {
        public int ProductId { get; set; }

        public int AttributeId { get; set; }

        public int DisplayOrder { get; set; }

        public virtual Product Product { get; set; }
    }
}