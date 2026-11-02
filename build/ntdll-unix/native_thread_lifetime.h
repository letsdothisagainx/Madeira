/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MADEIRA_NATIVE_THREAD_LIFETIME_H
#define MADEIRA_NATIVE_THREAD_LIFETIME_H
#include <stdint.h>
/* Embedded in native TLS; never allocate it from the FEX arena. All list
 * operations hold the native group lock. Detach before pthread TLS dies. */
struct madeira_native_thread
{
    struct madeira_native_thread *next;
    void *owner, *teb;
    uint64_t lease;
    unsigned pid, tid, cancelled, exit_status;
};
static inline void madeira_native_thread_link(struct madeira_native_thread **head,
        struct madeira_native_thread *node, void *owner, uint64_t lease, void *teb, unsigned pid, unsigned tid)
{
    if (node->owner || !owner || !lease || !teb || !pid || !tid) return;
    *node=(struct madeira_native_thread){*head,owner,teb,lease,pid,tid,0,0}; *head=node;
}
static inline void madeira_native_thread_unlink(struct madeira_native_thread **head,struct madeira_native_thread *node)
{
    while (*head && *head != node) head=&(*head)->next;
    if (*head) *head=node->next;
    node->next=0; node->owner=0;
}
static inline int madeira_native_thread_cancel(struct madeira_native_thread *head,
        void *owner,uint64_t lease,void *teb,unsigned pid,unsigned tid,unsigned status)
{
    for (;head;head=head->next)
        if (head->owner==owner && head->lease==lease && head->teb==teb && head->pid==pid && head->tid==tid)
        { head->exit_status=status; __atomic_store_n(&head->cancelled,1,__ATOMIC_RELEASE); return 1; }
    return 0;
}
#endif
