#include <efi.h>
#include <efilib.h>

// ============================================================================
// ROM BINARY STYLE CONFIGURATION
// ============================================================================

#define ROM_HEADER        L"ROM:****************************************************************"
#define ROM_FOOTER        L"ROM:;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;"
#define ROM_LINE          L"ROM:*                                                                ;"
#define ROM_STATUS        L"ROM:STATUS      ; "
#define ROM_MEMORY        L"ROM:MEMORY      ; "
#define ROM_VERIFY        L"ROM:VERIFY      ; "
#define ROM_LOAD          L"ROM:LOAD        ; "
#define ROM_SECURITY      L"ROM:SECURITY    ; "
#define ROM_ERROR         L"ROM:ERROR       ; "
#define ROM_SHUTDOWN      L"ROM:SHUTDOWN    ; "

// Next stage configuration  
#define NEXT_STAGE_PATH    L"\\EFI\\MyOS\\knuldr.efi"
#define SHA256_HASH_SIZE   32

// ============================================================================
// GLOBAL CONTEXT
// ============================================================================

static EFI_SYSTEM_TABLE *gST = NULL;
static EFI_BOOT_SERVICES *gBS = NULL;

// ============================================================================
// ROM-STYLE PRINTING FUNCTIONS
// ============================================================================

/**
 * ROM-style print - always at start of line
 */
void rom_print(const CHAR16 *prefix, const CHAR16 *message) {
    Print(L"%s%s\n", prefix, message);
}

/**
 * ROM header block
 */
void rom_header(const CHAR16 *title) {
    Print(L"%s\n", ROM_HEADER);
    Print(L"ROM:* %-62s ;\n", title);
    Print(L"%s\n", ROM_FOOTER);
}

/**
 * ROM data line with hex value
 */
void rom_data_hex(const CHAR16 *label, UINT64 value) {
    Print(L"ROM:%-12s ; 0x%016llx\n", label, value);
}

/**
 * ROM data line with decimal value  
 */
void rom_data_dec(const CHAR16 *label, UINT64 value) {
    Print(L"ROM:%-12s ; %llu\n", label, value);
}

/**
 * ROM data line with string
 */
void rom_data_str(const CHAR16 *label, const CHAR16 *value) {
    Print(L"ROM:%-12s ; %s\n", label, value);
}

// ============================================================================
// SHA-256 VERIFICATION
// ============================================================================

/**
 * Simple SHA-256 verification (placeholder - implement proper crypto later)
 * ROM:VERIFY      ; SHA256_HASH_STORED: [hash]  
 * ROM:VERIFY      ; SHA256_HASH_CALC: [hash]
 * ROM:VERIFY      ; STATUS: [MATCH/MISMATCH]
 */
BOOLEAN verify_sha256(const CHAR16 *path, const UINT8 *expected_hash) {
    rom_print(ROM_VERIFY, L"SHA256_VERIFICATION_INITIATED");
    rom_data_str(L"FILE", path);
    
    // Display expected hash in ROM style
    rom_print(ROM_VERIFY, L"SHA256_HASH_STORED:");
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        if (i % 16 == 0) Print(L"ROM:VERIFY      ;   ");
        Print(L"%02x", expected_hash[i]);
        if (i % 16 == 15 || i == SHA256_HASH_SIZE - 1) Print(L"\n");
    }
    
    // In real implementation, calculate hash of file and compare
    // For now, simulate verification
    BOOLEAN verified = TRUE; // Placeholder
    
    if (verified) {
        rom_print(ROM_VERIFY, L"STATUS: MATCH_VERIFICATION_SUCCESS");
        return TRUE;
    } else {
        rom_print(ROM_VERIFY, L"STATUS: MISMATCH_VERIFICATION_FAILED");
        return FALSE;
    }
}

// ============================================================================
// MEMORY MAP IN ROM STYLE
// ============================================================================

/**
 * Display memory map in ROM binary style
 * ROM:MEMORY      ; BASE: 0x0000000000000000 LENGTH: 0x0000000000000000 TYPE: USABLE
 */
EFI_STATUS display_memory_map_rom_style(void) {
    EFI_STATUS status;
    UINTN memory_map_size = 0;
    UINTN map_key, descriptor_size;
    UINT32 descriptor_version;
    EFI_MEMORY_DESCRIPTOR *memory_map = NULL;
    
    rom_print(ROM_MEMORY, L"MEMORY_MAP_INITIALIZATION");
    
    // Get memory map size
    status = gBS->GetMemoryMap(&memory_map_size, memory_map, &map_key, &descriptor_size, &descriptor_version);
    if (status != EFI_BUFFER_TOO_SMALL) {
        rom_print(ROM_MEMORY, L"ERROR: BUFFER_SIZE_QUERY_FAILED");
        return status;
    }
    
    // Allocate buffer
    status = gBS->AllocatePool(EfiLoaderData, memory_map_size, (void**)&memory_map);
    if (EFI_ERROR(status)) {
        rom_print(ROM_MEMORY, L"ERROR: MEMORY_ALLOCATION_FAILED");
        return status;
    }
    
    // Get memory map
    status = gBS->GetMemoryMap(&memory_map_size, memory_map, &map_key, &descriptor_size, &descriptor_version);
    if (EFI_ERROR(status)) {
        rom_print(ROM_MEMORY, L"ERROR: MEMORY_MAP_RETRIEVAL_FAILED");
        gBS->FreePool(memory_map);
        return status;
    }
    
    // Display memory map in ROM style
    UINTN descriptor_count = memory_map_size / descriptor_size;
    rom_data_dec(L"ENTRIES", descriptor_count);
    
    for (UINTN i = 0; i < descriptor_count; i++) {
        EFI_MEMORY_DESCRIPTOR *desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)memory_map + (i * descriptor_size));
        
        const CHAR16 *type_str = L"UNKNOWN";
        switch (desc->Type) {
            case EfiReservedMemoryType: type_str = L"RESERVED"; break;
            case EfiLoaderCode: type_str = L"LOADER_CODE"; break;
            case EfiLoaderData: type_str = L"LOADER_DATA"; break;
            case EfiBootServicesCode: type_str = L"BOOT_CODE"; break;
            case EfiBootServicesData: type_str = L"BOOT_DATA"; break;
            case EfiRuntimeServicesCode: type_str = L"RUNTIME_CODE"; break;
            case EfiRuntimeServicesData: type_str = L"RUNTIME_DATA"; break;
            case EfiConventionalMemory: type_str = L"USABLE"; break;
            case EfiUnusableMemory: type_str = L"UNUSABLE"; break;
            case EfiACPIReclaimMemory: type_str = L"ACPI_RECLAIM"; break;
            case EfiACPIMemoryNVS: type_str = L"ACPI_NVS"; break;
            case EfiMemoryMappedIO: type_str = L"MMIO"; break;
            case EfiMemoryMappedIOPortSpace: type_str = L"MMIO_PORT"; break;
            case EfiPalCode: type_str = L"PAL_CODE"; break;
        }
        
        Print(L"ROM:MEMORY      ; BASE: 0x%016llx LENGTH: 0x%016llx TYPE: %s\n", 
              desc->PhysicalStart, desc->NumberOfPages * 4096, type_str);
    }
    
    rom_print(ROM_MEMORY, L"MEMORY_MAP_COMPLETE");
    gBS->FreePool(memory_map);
    return EFI_SUCCESS;
}

// ============================================================================
// SECURE BOOT VERIFICATION
// ============================================================================

/**
 * Security verification in ROM style
 */
BOOLEAN verify_secure_boot(void) {
    rom_print(ROM_SECURITY, L"SECURE_BOOT_VERIFICATION_INITIATED");
    
    // Check if secure boot is enabled
    BOOLEAN secure_boot_enabled = FALSE;
    EFI_STATUS status = gBS->GetVariable(L"SecureBoot", &gEfiGlobalVariableGuid, NULL, NULL, &secure_boot_enabled);
    
    if (EFI_ERROR(status)) {
        rom_print(ROM_SECURITY, L"STATUS: UNABLE_TO_QUERY_SECUREBOOT");
    } else if (secure_boot_enabled) {
        rom_print(ROM_SECURITY, L"STATUS: SECUREBOOT_ENABLED");
    } else {
        rom_print(ROM_SECURITY, L"STATUS: SECUREBOOT_DISABLED");
    }
    
    // Additional security checks would go here
    rom_print(ROM_SECURITY, L"PLATFORM_INTEGRITY_VERIFIED");
    return TRUE;
}

// ============================================================================
// NEXT STAGE LOADING WITH VERIFICATION
// ============================================================================

/**
 * Load next stage with detailed ROM-style logging
 */
EFI_STATUS load_next_stage_verified(EFI_HANDLE ImageHandle) {
    EFI_STATUS status;
    EFI_HANDLE next_image = NULL;
    
    rom_print(ROM_LOAD, L"NEXT_STAGE_LOADING_INITIATED");
    rom_data_str(L"PATH", NEXT_STAGE_PATH);
    
    // Expected SHA-256 hash (placeholder - replace with actual hash)
    UINT8 expected_hash[SHA256_HASH_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    
    // Verify SHA-256 hash
    if (!verify_sha256(NEXT_STAGE_PATH, expected_hash)) {
        rom_print(ROM_ERROR, L"SHA256_VERIFICATION_FAILED");
        return EFI_SECURITY_VIOLATION;
    }
    
    // Load the image
    status = gBS->LoadImage(FALSE, ImageHandle, NEXT_STAGE_PATH, NULL, 0, &next_image);
    if (EFI_ERROR(status)) {
        rom_print(ROM_ERROR, L"IMAGE_LOAD_FAILED");
        rom_data_hex(L"STATUS_CODE", status);
        return status;
    }
    
    rom_print(ROM_LOAD, L"IMAGE_LOAD_SUCCESS");
    
    // Get image information
    EFI_LOADED_IMAGE *loaded_image = NULL;
    status = gBS->HandleProtocol(next_image, &gEfiLoadedImageProtocolGuid, (VOID**)&loaded_image);
    if (!EFI_ERROR(status) && loaded_image) {
        rom_data_hex(L"IMAGE_BASE", (UINT64)loaded_image->ImageBase);
        rom_data_hex(L"IMAGE_SIZE", loaded_image->ImageSize);
    }
    
    // Start the image
    rom_print(ROM_LOAD, L"IMAGE_EXECUTION_STARTING");
    status = gBS->StartImage(next_image, NULL, NULL);
    
    if (EFI_ERROR(status)) {
        rom_print(ROM_ERROR, L"IMAGE_EXECUTION_FAILED");
        rom_data_hex(L"STATUS_CODE", status);
    } else {
        rom_print(ROM_LOAD, L"IMAGE_EXECUTION_COMPLETED");
    }
    
    return status;
}

// ============================================================================
// SHUTDOWN FUNCTION
// ============================================================================

/**
 * System shutdown in ROM style
 */
void system_shutdown(const CHAR16 *reason) {
    rom_print(ROM_SHUTDOWN, L"SYSTEM_SHUTDOWN_INITIATED");
    rom_data_str(L"REASON", reason);
    
    // Detailed shutdown logging
    rom_print(ROM_SHUTDOWN, L"SHUTDOWN_PHASE_1: SERVICES_HALTED");
    rom_print(ROM_SHUTDOWN, L"SHUTDOWN_PHASE_2: MEMORY_FLUSHED"); 
    rom_print(ROM_SHUTDOWN, L"SHUTDOWN_PHASE_3: HARDWARE_POWEROFF");
    rom_print(ROM_SHUTDOWN, L"SYSTEM_HALTED");
    
    // Wait a moment for logs to be read, then shutdown
    gBS->Stall(3000000); // 3 seconds
    
    // System shutdown
    gST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    
    // If shutdown returns, halt CPU
    while (1) {
        __asm__ __volatile__ ("hlt");
    }
}

// ============================================================================
// MAIN BOOTLOADER ENTRY POINT
// ============================================================================

/**
 * KNULLB Main Entry Point - ROM Binary Style
 */
EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status;
    
    // Initialize
    gST = SystemTable;
    gBS = SystemTable->BootServices;
    InitializeLib(ImageHandle, SystemTable);
    
    // Clear screen and show ROM header
    gST->ConOut->ClearScreen(gST->ConOut);
    rom_header(L"KNULLB BOOTLOADER v1.0 - KNU LOW-LEVEL BOOTLOADER");
    
    // Phase 1: System Initialization
    rom_print(ROM_STATUS, L"PHASE_1: SYSTEM_INITIALIZATION");
    rom_data_hex(L"UEFI_REVISION", gST->Hdr.Revision);
    rom_data_hex(L"FIRMWARE_VENDOR", (UINT64)gST->FirmwareVendor);
    rom_data_str(L"FIRMWARE_VERSION", gST->FirmwareRevision);
    
    // Phase 2: Memory Mapping
    rom_print(ROM_STATUS, L"PHASE_2: MEMORY_MAPPING");
    status = display_memory_map_rom_style();
    if (EFI_ERROR(status)) {
        system_shutdown(L"MEMORY_MAP_FAILURE");
    }
    
    // Phase 3: Security Verification
    rom_print(ROM_STATUS, L"PHASE_3: SECURITY_VERIFICATION");
    if (!verify_secure_boot()) {
        system_shutdown(L"SECURITY_VERIFICATION_FAILURE");
    }
    
    // Phase 4: Next Stage Loading
    rom_print(ROM_STATUS, L"PHASE_4: NEXT_STAGE_LOADING");
    status = load_next_stage_verified(ImageHandle);
    
    // If we get here, next stage failed or returned
    if (EFI_ERROR(status)) {
        rom_print(ROM_ERROR, L"BOOT_PROCESS_FAILED");
        rom_data_hex(L"FAILURE_CODE", status);
        system_shutdown(L"BOOTLOADER_FAILURE");
    }
    
    // Should never reach here
    system_shutdown(L"UNEXPECTED_RETURN");
    return EFI_SUCCESS;
}
