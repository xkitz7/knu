#ifndef MEMORY_H
#define MEMORY_H

#include <efi.h>
#include <efilib.h>

// memory types
typedef enum {
    MEMORY_USABLE = 0,
    MEMORY_RESERVED,
    MEMORY_ACPI_RECLAIM,
    MEMORY_ACPI_NVS,
    MEMORY_BAD
} memory_type_t;

// memory map structure
typedef struct {
    UINT64 base_address;
    UINT64 length;
    memory_type_t type;
} memory_map_entry_t;

// function prototypes
EFI_STATUS initialize_memory_map(EFI_SYSTEM_TABLE *SystemTable, UINTN *map_key, UINTN *descriptor_size, UINT32 *descriptor_version);
void print_memory_map(EFI_SYSTEM_TABLE *SystemTable);
EFI_STATUS get_memory_map(EFI_SYSTEM_TABLE *SystemTable, UINTN *memory_map_size, EFI_MEMORY_DESCRIPTOR **memory_map, UINTN *map_key, UINTN *descriptor_size, UINT32 *descriptor_version);

#endif
