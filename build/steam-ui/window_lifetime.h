/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native window identity only. Callers serialize access; no Wine/UI calls. */
#ifndef MADEIRA_WINDOW_LIFETIME_H
#define MADEIRA_WINDOW_LIFETIME_H
#include <stdint.h>
#include <stddef.h>
/* Wine server/user.c puts the table index in the low 16 bits and the
 * generation in the high 16 bits. Direct low-half indexing covers every
 * canonical user handle without a cache eviction or capacity fallback. */
#define MADEIRA_WINDOW_ROWS 65536
struct madeira_window_ticket { uint64_t serial; uint32_t hwnd,pid,tid,alive; };
struct madeira_window_registry { uint64_t next;struct madeira_window_ticket rows[MADEIRA_WINDOW_ROWS]; };
static inline struct madeira_window_ticket madeira_window_capture(const struct madeira_window_registry *r,uintptr_t hwnd)
{
    struct madeira_window_ticket unknown={0,0,0,0,0};
    if(!hwnd||hwnd>UINT32_MAX)return unknown;
    struct madeira_window_ticket row=r->rows[hwnd&0xffff];
    if(!row.serial){unknown.hwnd=(uint32_t)hwnd;return unknown;}
    if(row.hwnd!=(uint32_t)hwnd){unknown.hwnd=(uint32_t)hwnd;unknown.alive=2;return unknown;}
    return row;
}
static inline struct madeira_window_ticket madeira_window_owner(struct madeira_window_ticket t,uint32_t pid,uint32_t tid,int strict_thread)
{
    if(t.serial&&((pid&&t.pid!=pid)||(strict_thread&&tid&&t.tid!=tid))){t.serial=0;t.alive=2;}
    return t;
}
static inline uint64_t madeira_window_birth(struct madeira_window_registry *r,uint32_t hwnd,uint32_t pid,uint32_t tid)
{
    if(!hwnd)return 0;
    struct madeira_window_ticket *p=&r->rows[hwnd&0xffff];
    if(p->alive)
        return p->hwnd==hwnd&&p->pid==pid&&p->tid==tid?p->serial:0;
    if(r->next==UINT64_MAX)return 0;
    *p=(struct madeira_window_ticket){++r->next,hwnd,pid,tid,1};return p->serial;
}
static inline int madeira_window_same(const struct madeira_window_registry *r,struct madeira_window_ticket t)
{
    if(!t.hwnd)return !t.serial&&!t.alive;
    struct madeira_window_ticket p=r->rows[t.hwnd&0xffff];
    if(!t.serial)return !t.alive&&!p.serial;
    return p.serial==t.serial&&p.hwnd==t.hwnd&&p.pid==t.pid&&p.tid==t.tid;
}
static inline int madeira_window_can_present(const struct madeira_window_registry *r,struct madeira_window_ticket t)
{
    return madeira_window_same(r,t)&&(!t.serial||(t.alive==1&&r->rows[t.hwnd&0xffff].alive));
}
static inline int madeira_window_can_cleanup(const struct madeira_window_registry *r,struct madeira_window_ticket t,uint64_t layer_serial)
{
    /* A retirement may outlive its registry row. It can still remove its own
     * old layer, but never a replacement layer carrying a newer ticket. */
    return t.serial?layer_serial==t.serial:(!layer_serial&&madeira_window_same(r,t));
}
static inline int madeira_window_retire(struct madeira_window_registry *r,struct madeira_window_ticket t)
{
    if(!t.serial||!madeira_window_same(r,t)||!r->rows[t.hwnd&0xffff].alive)return 0;
    r->rows[t.hwnd&0xffff].alive=0;return 1;
}
static inline void madeira_window_end_session(struct madeira_window_registry *r)
{
    /* Keep identities and monotonic serials: queued old work must never gain
     * permission again when a replacement native server reuses its HWNDs. */
    for(size_t i=0;i<MADEIRA_WINDOW_ROWS;i++)r->rows[i].alive=0;
}
#endif
