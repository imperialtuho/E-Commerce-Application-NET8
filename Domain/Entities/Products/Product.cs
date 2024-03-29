﻿using Domain.Common;
using Domain.Entities.RelationalEntities;
using Domain.Entities.RelationalEntity;

namespace Domain.Entities
{
    public class Product : BaseEntity<int>
    {
        public required string Name { get; set; }

        public string? Description { get; set; }

        public string? FullDescription { get; set; }

        public virtual ICollection<ProductCategories> ProductCategories { get; set; } = new HashSet<ProductCategories>();

        public virtual ICollection<ProductAttributes> ProductAttributes { get; set; } = new HashSet<ProductAttributes>();
    }
}