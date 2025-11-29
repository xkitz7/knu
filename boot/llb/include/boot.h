#ifndef BOOT_H
#define BOOT_H

#include <efi.h>
#include <efilib.h>

// bl info structure
typedef struct {
    CHAR16 version[32];
    UINT64 timestamp;
    UINT64 features;
} boot_info_t;

// paths
#define NEXT_STAGE_PATH L"\\EFI\\MY\\knuldr.efi"
#define FALLBACK_SHELL_PATH L"\\EFI\\BOOT\\shellx64.efi"

// flags
#define FEATURE_MMAP_AVAILABLE   0x0001
#define FEATURE_GRAPHICS_AVAILABLE 0x0002
#define FEATURE_SECURE_BOOT      0x0004

// function prototypes
EFI_STATUS initialize_boot_services(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);
EFI_STATUS load_next_stage(EFI_HANDLE ImageHandle, CHAR16 *path, EFI_HANDLE *image_handle);
EFI_STATUS start_image(EFI_HANDLE image_handle);
void print_boot_info(EFI_SYSTEM_TABLE *SystemTable, boot_info_t *info);
EFI_STATUS fallback_to_shell(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);
BOOLEAN verify_next_stage(CHAR16 *path);

#endif
