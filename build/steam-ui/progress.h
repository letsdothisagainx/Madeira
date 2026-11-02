/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Bounded metadata counters. No input values, window text or bitmap contents. */
#ifndef MADEIRA_STEAM_UI_PROGRESS_H
#define MADEIRA_STEAM_UI_PROGRESS_H
#include <stdint.h>
#include <stddef.h>
#define MADEIRA_UI_PROGRESS_SLOTS 32
enum madeira_ui_progress_kind {
    MADEIRA_UI_POLL, MADEIRA_UI_FLUSH, MADEIRA_UI_DEQUEUED,
    MADEIRA_UI_DISPATCH_BEGIN, MADEIRA_UI_DISPATCH_RETURN, MADEIRA_UI_DISPATCH_FAILED,
    MADEIRA_UI_INPUT_BEGIN, MADEIRA_UI_INPUT_RETURN, MADEIRA_UI_INPUT_FAILED,
    MADEIRA_UI_PROGRESS_KINDS
};
struct madeira_ui_progress_slot {
    uint64_t key, count[MADEIRA_UI_PROGRESS_KINDS], last_ns[MADEIRA_UI_PROGRESS_KINDS], input_hwnd;
    uint32_t input_message;
};
struct madeira_ui_progress_snapshot {
    uint64_t count[MADEIRA_UI_PROGRESS_KINDS], last_ns[MADEIRA_UI_PROGRESS_KINDS], input_hwnd;
    uint32_t input_message;
};
static inline int madeira_ui_input_message(unsigned message)
{
    return (message >= 0x100 && message <= 0x109) || (message >= 0x200 && message <= 0x20e) || message == 0xff;
}
static inline int madeira_ui_progress_add(struct madeira_ui_progress_slot *slots,
                                          uint32_t pid, uint32_t tid, unsigned kind, uint64_t now,uintptr_t hwnd,unsigned message)
{
    if (!pid || !tid || kind >= MADEIRA_UI_PROGRESS_KINDS) return 0;
    uint64_t key=((uint64_t)pid<<32)|tid;
    for(unsigned i=0;i<MADEIRA_UI_PROGRESS_SLOTS;i++)
    {
        uint64_t old=__atomic_load_n(&slots[i].key,__ATOMIC_RELAXED);
        if(!old)__atomic_compare_exchange_n(&slots[i].key,&old,key,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED);
        if(__atomic_load_n(&slots[i].key,__ATOMIC_RELAXED)!=key)continue;
        __atomic_fetch_add(&slots[i].count[kind],1,__ATOMIC_RELAXED);
        __atomic_store_n(&slots[i].last_ns[kind],now,__ATOMIC_RELAXED);
        if(kind==MADEIRA_UI_INPUT_RETURN)
        {
            __atomic_store_n(&slots[i].input_hwnd,hwnd<=UINT32_MAX?hwnd:0,__ATOMIC_RELAXED);
            __atomic_store_n(&slots[i].input_message,message,__ATOMIC_RELAXED);
        }
        return 1;
    }
    return 0;
}
static inline int madeira_ui_progress_read(const struct madeira_ui_progress_slot *slots,
                                           uint32_t pid,uint32_t tid,struct madeira_ui_progress_snapshot *out)
{
    if(!pid||!tid)return 0;
    uint64_t key=((uint64_t)pid<<32)|tid;
    for(unsigned i=0;i<MADEIRA_UI_PROGRESS_SLOTS;i++)if(__atomic_load_n(&slots[i].key,__ATOMIC_RELAXED)==key)
    {
        for(unsigned j=0;j<MADEIRA_UI_PROGRESS_KINDS;j++)
        {
            out->count[j]=__atomic_load_n(&slots[i].count[j],__ATOMIC_RELAXED);
            out->last_ns[j]=__atomic_load_n(&slots[i].last_ns[j],__ATOMIC_RELAXED);
        }
        out->input_hwnd=__atomic_load_n(&slots[i].input_hwnd,__ATOMIC_RELAXED);
        out->input_message=__atomic_load_n(&slots[i].input_message,__ATOMIC_RELAXED);
        return 1;
    }
    return 0;
}
void winios_ui_progress_event(unsigned kind,unsigned message,uintptr_t hwnd);
int winios_ui_progress_snapshot(uint32_t pid,uint32_t tid,struct madeira_ui_progress_snapshot *out);
#endif
