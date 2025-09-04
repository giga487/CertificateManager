using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Common
{
    public partial class Utility
    {
        public class LimitedQueue<T>
        {
            private readonly int maxSize;
            private readonly ConcurrentQueue<T> queue;
            public int Count
            {
                get
                {
                    try
                    {
                        return queue.Count;
                    }
                    catch(Exception)
                    {
                        return 0;
                    }
                }
            }
            public LimitedQueue(int maxSize)
            {
                this.maxSize = maxSize;
                this.queue = new ConcurrentQueue<T>();
            }

            public void Add(T item)
            {
                if(queue.Count >= maxSize)
                {
                    queue.TryDequeue(out var _); // Rimuove l'elemento più vecchio
                }

                queue.Enqueue(item);
            }

            public IEnumerable<T> GetItems(bool reverted = false)
            {
                if(reverted)
                {
                    var list = queue.ToList();
                    list.Reverse();
                    return list;
                }

                return queue.ToList();
            }

            public IEnumerable<T> Flush()
            {
                while(queue.TryDequeue(out T? item))
                {
                    yield return item;
                }
            }
        }


    }
}
