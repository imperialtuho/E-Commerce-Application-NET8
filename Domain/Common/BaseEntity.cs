namespace Domain.Common
{
    public class BaseEntity<TId>
    {
        public TId Id { get; set; }
    }
}