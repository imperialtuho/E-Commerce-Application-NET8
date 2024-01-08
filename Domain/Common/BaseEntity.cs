namespace Domain.Common
{
    public class BaseEntity<TId>
    {
        public TId Id { get; set; }

        public DateTime? CreatedDate { get; set; }

        public string CreatedBy { get; set; }

        public DateTime? ModifiedDate { get; set; } = null!;

        public string ModifiedBy { get; set; } = null!;

        public bool IsDeleted { get; set; }
    }
}