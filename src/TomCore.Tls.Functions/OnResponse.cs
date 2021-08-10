using System;
using System.Collections.Immutable;
using System.Net;
using System.Threading.Tasks;
using Azure;

namespace TomCore.Tls.Functions
{
    internal class OnResponse
    {
        public static OnResponse<T> Get<T>()
        {
            return new OnResponse<T>(ImmutableDictionary<int, Func<Task<T>>>.Empty);
        }
    }

    internal class OnResponse<T> : OnResponse
    {
        readonly ImmutableDictionary<int, Func<Task<T>>> _dictionary;

        public OnResponse(ImmutableDictionary<int, Func<Task<T>>> dictionary)
        {
            _dictionary = dictionary;
        }

        public OnResponse<T> ForCode(int statusCode, Func<Task<T>> task)
        {
            if (!Enum.TryParse(typeof(HttpStatusCode), statusCode.ToString(), true, out _))
            {
                throw new ArgumentOutOfRangeException(statusCode.ToString());
            }

            if (statusCode is > 200 and < 300)
            {
                throw new ArgumentOutOfRangeException(statusCode.ToString());
            }

            var dict = _dictionary.Add(statusCode, task);
            return new OnResponse<T>(dict);
        }

        public async Task<T> Evaluate<TS>(Func<Task<TS>> runQuery, Func<TS, Task<T>> success)
        {
            try
            {
                return await success(await runQuery());
            }
            catch (RequestFailedException e)
            {
                if (_dictionary.TryGetValue(e.Status, out var func2))
                {
                    return await func2();
                }

                throw;
            }
        }
    }
}