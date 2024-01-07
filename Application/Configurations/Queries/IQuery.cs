namespace Application.Configurations.Queries
{
    public interface IQuery<out TResult> : IRequest<TResult>
    {
    }
}