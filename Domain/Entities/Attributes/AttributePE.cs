using Domain.Common;

namespace Domain.Entities.Attributes
{
    public class AttributePE : BaseEntity<int>
    {
        public string Name { get; set; }

        public string? Description { get; set; }

        public string Value { get; set; }
    }
}