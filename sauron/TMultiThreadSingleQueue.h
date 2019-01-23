#ifndef TMULTITHREADSINGLEQUEUE_H
#define TMULTITHREADSINGLEQUEUE_H

/*
   Multi Threading Queue After:
   M. Michael and M. Scott. "Nonblocking algorithms and preemption-safe locking on
                             multiprogrammed shared - memory multiprocessors."
      Journal of Parallel and Distributed Computing, 51(1):1–26, 1998.

   N.B.: This is the template version: use a pointer for the template parameter
         in order to preserve the "move semantics" as opposed to the "copy semantics"
         inherent to the templated form.
*/

#if _MSC_VER > 1000
#pragma warning (disable: 4786)
#pragma warning (disable: 4748)
#pragma warning (disable: 4103)
#endif /* _MSC_VER > 1000 */

#include <afx.h>
#include <afxwin.h>

template <typename T>
class CTMultiThreadSingleQueue
{
   /*template <typename T>*/
   class CTNode
   {
   public:
      CTNode(void) { pNextNode = NULL; };
      ~CTNode(void) {};

      CTNode* pNextNode;
      T       pValuePointer;

   private:
      // Don't allow these sorts of things
      CTNode( const CTNode& ) {};
      CTNode& operator = ( const CTNode& ){ return( *this ); };
   };

public:
   CTMultiThreadSingleQueue(void);
   virtual ~CTMultiThreadSingleQueue(void);

private:
   // Don't allow these sorts of things
   CTMultiThreadSingleQueue( const CTMultiThreadSingleQueue& ) {};
   CTMultiThreadSingleQueue& operator = ( const CTMultiThreadSingleQueue& ){ return( *this ); };

protected:
   // Critical sections guarding Head and Tail code sections
   CCriticalSection m_HeadCriticalSection;
   CCriticalSection m_TailCriticalSection;
   // The queue, two pointers to head and tail respectively
   CTNode* pHeadNode;
   CTNode* pTailNode;
   // Queue size
   volatile long m_Size;

public:
   // Enqueue, pass by value
   /*template <typename T>*/
   bool Push(T pNewValue);
   // Dequeue, pass by reference
   /*template <typename T>*/
   bool Pop (T& pValue);
   // for accurate sizes change the code to use the Interlocked functions calls
   long GetSize() { return m_Size; }
};

template <typename T> CTMultiThreadSingleQueue<T>::CTMultiThreadSingleQueue(void)
{
   // node = new node() # Allocate a free node
   // node next = NULL # Make it the only node in the linked list
   CTNode* pFirstNode = new CTNode;
   // The queue
   // QHead = QTail = node # Both Head and Tail point to it
   pHeadNode = pFirstNode;
   pTailNode = pFirstNode;
   // Queue size, dummy node counted off
   m_Size = 0;
   // QHlock = QTlock = FREE # Locks are initially free
}

template <typename T> CTMultiThreadSingleQueue<T>::~CTMultiThreadSingleQueue(void)
{
   T pDummyValue;
   while ( Pop(pDummyValue) ) ;
   if ( pHeadNode ) { try { delete pHeadNode; } catch(...) { NULL; } }
}

template <typename T> bool CTMultiThreadSingleQueue<T>::Push(T pNewValue)
{
   // node = new node() # Allocate a new node from the free list
   // node->next = NULL # Set next pointer of node to NULL
   CTNode* pNewNode = new CTNode;
   // node->value = value # Copy enqueued value into node
   pNewNode->pValuePointer = pNewValue;
   // lock(&QTlock) # Acquire Tail lock in order to access Tail
   CSingleLock singleLock(&m_TailCriticalSection);
   singleLock.Lock();
   // QTail->next = node # Link node at the end of the linked list
   pTailNode->pNextNode = pNewNode;
   // QTail = node # Swing Tail to node
   pTailNode = pNewNode;
   // Increment size - use InterlockedIncrement for accurate sizes
   // ::InterlockedIncrement(&m_Size);
   m_Size++;
   // unlock(&QTlock) # Release Tail lock
   singleLock.Unlock();
   return true;
}

template <typename T> bool CTMultiThreadSingleQueue<T>::Pop(T& pValue)
{
   // lock(&QH lock) # Acquire Head lock in order to access Head
   CSingleLock singleLock(&m_HeadCriticalSection);
   singleLock.Lock();
   // node = Q->Head # Read Head
   CTNode* pCurrentNode = pHeadNode;
   // new_head = node->next # Read next pointer
   CTNode* pNewHeadNode = pHeadNode->pNextNode;
   // if new_head == NULL # Is queue empty?
   if ( NULL == pNewHeadNode ) // # Queue was empty
   {
      //    unlock(&QH lock) # Release Head lock before return
      singleLock.Unlock();
      //    return FALSE
      return false;
   }
   // endif
   // *pvalue = new_head->value # Queue not empty. Read value before release
   pValue = pNewHeadNode->pValuePointer;
   // QHead = new_head # Swing Head to next node
   pHeadNode = pNewHeadNode;
   // decrement size - use InterlockedDecrement for accurate sizes
   // ::InterlockedDecrement(&m_Size);
   m_Size--;
   // unlock(&QH lock) # Release H lock
   singleLock.Unlock();
   // free(node) # Free node
   try { delete pCurrentNode; } catch(...) { NULL; }
   // return TRUE # Queue was not empty, dequeue succeeded
   return true;
}

#endif // ! defined(TMULTITHREADSINGLEQUEUE_H)

