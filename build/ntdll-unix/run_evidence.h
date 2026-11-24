/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Passive v1 wire ABI. Producers never wait, allocate, format or perform I/O.
 * All addresses describe metadata; no guest payload is recorded. */
#ifndef MADEIRA_RUN_EVIDENCE_H
#define MADEIRA_RUN_EVIDENCE_H
#include <stdint.h>
#define IOS_EVIDENCE_WORDS 48
#define IOS_EVIDENCE_RECORDS 1024
enum { IOS_EV_PROCESS=1, IOS_EV_MAIN=2, IOS_EV_ACCESS=3, IOS_EV_VM=4, IOS_EV_FRAME=5,
       IOS_EV_BACKING=6, IOS_EV_INFLIGHT=7, IOS_EV_COUNTERS=8 };
struct ios_evidence_record { uint64_t w[IOS_EVIDENCE_WORDS]; };
extern uint64_t ios_evidence_backing_file;
uint64_t ios_evidence_now(void);
void ios_runtime_register(uint64_t,uint64_t,unsigned,unsigned,uint64_t);
uint64_t ios_runtime_begin(unsigned,uint64_t);
void ios_runtime_end(unsigned,uint64_t);
void ios_runtime_identity(uint64_t *);
int ios_cs2_current_private_owner(uintptr_t);
void ios_evidence_emit(struct ios_evidence_record *);
int ios_evidence_emit_checked(struct ios_evidence_record *);
uint64_t ios_evidence_begin(unsigned op, uintptr_t address, uint64_t bytes, uint64_t generation, unsigned lock_scope);
uint64_t ios_evidence_begin_extent(unsigned, uintptr_t, uint64_t, uint64_t, unsigned, uint64_t);
void ios_evidence_end(uint64_t token, int result, int error);
void ios_evidence_access(struct ios_evidence_record *);
#endif
