using System;

namespace TomCore.Tls.Functions
{
    internal static class Guard
    {
        public static void NotNull<T>(T t, string name) where T : class
        {
            if (t is null)
            {
                throw new ArgumentNullException(name);
            }
        }
    }
}