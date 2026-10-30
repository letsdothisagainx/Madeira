/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 125hz
 * Madeira Converter Exception: see LICENSE-EXCEPTION.md */
#ifndef MADEIRA_SERVICE_PREPARE_H
#define MADEIRA_SERVICE_PREPARE_H
#include <stdint.h>
/* Every callback returns the real Win32/installer result. Only a confirmed
 * ERROR_SERVICE_DOES_NOT_EXIST permits installation. No registry fabrication. */
struct service_ops {
    uint32_t (*manager)(void);
    uint32_t (*query)(void);
    uint32_t (*install)(void);
    uint32_t (*start)(void);
};
static inline uint32_t prepare_service(const struct service_ops *ops)
{
    uint32_t error = ops->manager();
    if (error) return error;
    error = ops->query();
    if (error == 1060) {
        if ((error = ops->install())) return error;
        error = ops->query(); /* Exit zero alone is not registration. */
    }
    if (error) return error;
    return ops->start(); /* Must query genuine SERVICE_RUNNING afterwards. */
}
#endif
