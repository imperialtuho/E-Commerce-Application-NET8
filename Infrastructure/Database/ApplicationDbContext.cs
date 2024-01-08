using Domain.Entities;
using Domain.Entities.Attributes;
using Domain.Entities.Categories;
using Domain.Entities.Identity;
using Domain.Entities.RelationalEntities;
using Domain.Entities.RelationalEntity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection;

namespace Infrastructure.Database
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        public DbSet<AttributePE> Attributes { get; set; }

        public virtual DbSet<Product> Products { get; set; }

        public virtual DbSet<Category> Categories { get; set; }

        public virtual DbSet<ProductCategories> ProductCategories { get; set; }

        public virtual DbSet<ProductAttributes> ProductAttributes { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

            base.OnModelCreating(builder);

            builder.Entity<ProductAttributes>(entity =>
            {
                entity.HasOne(p => p.Product)
                      .WithMany(p => p.ProductAttributes)
                      .HasForeignKey(p => p.ProductId)
                      .OnDelete(DeleteBehavior.ClientSetNull)
                      .HasConstraintName("FK_ProductAttributes_Product");
            });

            builder.Entity<ProductCategories>(entity =>
            {
                entity.ToTable("ProductCategories");

                entity.HasIndex(e => new { e.ProductId, e.CategoryId })
                    .HasDatabaseName("idx_ProductId_CategoryId");

                entity.HasOne(d => d.Category)
                    .WithMany(p => p.ProductCategories)
                    .HasForeignKey(d => d.CategoryId)
                    .HasConstraintName("FK_ProductCategory_Categories");

                entity.HasOne(d => d.Product)
                    .WithMany(p => p.ProductCategories)
                    .HasForeignKey(d => d.ProductId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_ProductCategory_Products");
            });
        }
    }
}