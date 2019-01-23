#ifndef MULTITHREADSINGLEQUEUE_H
#define MULTITHREADSINGLEQUEUE_H

/*
   Multi Threading Queue After:
   M. Michael and M. Scott. "Nonblocking algorithms and preemption-safe locking on
                             multiprogrammed shared - memory multiprocessors."
      Journal of Parallel and Distributed Computing, 51(1):1–26, 1998.
*/

#if _MSC_VER > 1000
#pragma warning (disable: 4786)
#pragma warning (disable: 4748)
#pragma warning (disable: 4103)
#endif /* _MSC_VER > 1000 */

#include <afx.h>
#include <afxwin.h>

class CNode
{
public:
   CNode(void) { pNextNode = NULL; pValuePointer = NULL; };
   ~CNode(void) {};

   CNode* pNextNode;
   void*  pValuePointer;

private:
   // Don't allow these sorts of things
   CNode( const CNode& ) {};
   CNode& operator = ( const CNode& ){ return( *this ); };
};

class CMultiThreadSingleQueue
{
public:
   CMultiThreadSingleQueue(void);
   virtual ~CMultiThreadSingleQueue(void);

private:
   // Don't allow these sorts of things
   CMultiThreadSingleQueue( const CMultiThreadSingleQueue& ) {};
   CMultiThreadSingleQueue& operator = ( const CMultiThreadSingleQueue& ){ return( *this ); };

protected:
   // Critical sections guarding Head and Tail code sections
   CCriticalSection m_HeadCriticalSection;
   CCriticalSection m_TailCriticalSection;
   // The queue, two pointers to head and tail respectively
   CNode* pHeadNode;
   CNode* pTailNode;
   // Queue size
   volatile long m_Size;

public:
   // Enqueue
   bool Push(void* pNewValue);
   // Dequeue, pass a pointer by reference
   bool Pop (void*& pValue);
   // for accurate sizes change the code to use the Interlocked functions calls
   long GetSize() { return m_Size; }
};

#endif // ! defined(MULTITHREADSINGLEQUEUE_H)

