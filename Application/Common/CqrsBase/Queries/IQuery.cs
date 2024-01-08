namespace Application.Common.CqrsBase.Queries
{
    public interface IQuery<out TResult> : IRequest<TResult>
    {
    }
}