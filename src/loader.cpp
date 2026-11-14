#include <inmemory_pe/loader.hpp>
#include <cstring>
#include <utility>

namespace inmemory_pe {

    namespace {
        class loader_category_impl : public std::error_category {
        public:
            [[nodiscard]] const char* name() const noexcept override {
                return "inmemory_pe_loader";
            }

            [[nodiscard]] std::string message(int ev) const override {
                switch (static_cast<loader_errc>(ev)) {
                    case loader_errc::success:
                        return "Operation succeeded";
                    case loader_errc::invalid_dos_header:
                        return "Invalid DOS signature (IMAGE_DOS_SIGNATURE 0x5A4D mismatch)";
                    case loader_errc::invalid_nt_signature:
                        return "Invalid NT signature (IMAGE_NT_SIGNATURE 0x00004550 mismatch)";
                    case loader_errc::unsupported_architecture:
                        return "Unsupported binary machine type (requires AMD64 / 0x8664)";
                    case loader_errc::allocation_failed:
                        return "VirtualAlloc failed to reserve and commit image memory";
                    case loader_errc::relocation_failed:
                        return "Corrupt or invalid base relocation directory table";
                    case loader_errc::import_resolution_failed:
                        return "Failed to resolve dependent library or function export via IAT";
                    case loader_errc::tls_execution_failed:
                        return "Unhandled exception during TLS callback invocation";
                    case loader_errc::exception_registration_failed:
                        return "RtlAddFunctionTable failed to register x64 unwind entries";
                    case loader_errc::entry_point_failed:
                        return "EntryPoint returned failure (FALSE) on DLL_PROCESS_ATTACH";
                    default:
                        return "Unknown loader error";
                }
            }
        };

        const loader_category_impl k_category_instance{};
    }

    const std::error_category& loader_category() noexcept {
        return k_category_instance;
    }

    pe_image::~pe_image() noexcept {
        cleanup();
    }

    pe_image::pe_image(pe_image&& other) noexcept
        : base_address_(std::exchange(other.base_address_, nullptr)),
          image_size_(std::exchange(other.image_size_, 0)),
          entry_point_(std::exchange(other.entry_point_, 0)),
          seh_registered_(std::exchange(other.seh_registered_, false)),
          pdata_table_(std::exchange(other.pdata_table_, nullptr)),
          pdata_entries_(std::exchange(other.pdata_entries_, 0)) {}

    pe_image& pe_image::operator=(pe_image&& other) noexcept {
        if (this != &other) {
            pe_image temp(std::move(other));
            swap(temp);
        }
        return *this;
    }

    void pe_image::swap(pe_image& other) noexcept {
        using std::swap;
        swap(base_address_, other.base_address_);
        swap(image_size_, other.image_size_);
        swap(entry_point_, other.entry_point_);
        swap(seh_registered_, other.seh_registered_);
        swap(pdata_table_, other.pdata_table_);
        swap(pdata_entries_, other.pdata_entries_);
    }

    void pe_image::cleanup() noexcept {
        if (seh_registered_ && pdata_table_ != nullptr) {
            RtlDeleteFunctionTable(pdata_table_);
            seh_registered_ = false;
            pdata_table_ = nullptr;
            pdata_entries_ = 0;
        }

        if (base_address_ != nullptr) {
            VirtualFree(base_address_, 0, MEM_RELEASE);
            base_address_ = nullptr;
            image_size_ = 0;
            entry_point_ = 0;
        }
    }

    std::error_code pe_image::validate_headers(
        std::span<const std::uint8_t> raw_bytes,
        const IMAGE_NT_HEADERS64*& out_nt_headers
    ) const noexcept {
        if (raw_bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
            return loader_errc::invalid_dos_header;
        }

        const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_bytes.data());
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            return loader_errc::invalid_dos_header;
        }

        if (raw_bytes.size() < static_cast<std::size_t>(dos_header->e_lfanew) + sizeof(IMAGE_NT_HEADERS64)) {
            return loader_errc::invalid_nt_signature;
        }

        const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw_bytes.data() + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            return loader_errc::invalid_nt_signature;
        }

        if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            return loader_errc::unsupported_architecture;
        }

        out_nt_headers = nt_headers;
        return loader_errc::success;
    }

    std::error_code pe_image::allocate_and_map_sections(
        std::span<const std::uint8_t> raw_bytes,
        const IMAGE_NT_HEADERS64* nt_headers,
        load_result& out_result
    ) noexcept {
        const std::size_t size_of_image = nt_headers->OptionalHeader.SizeOfImage;
        const std::size_t size_of_headers = nt_headers->OptionalHeader.SizeOfHeaders;

        void* image_base = VirtualAlloc(
            nullptr,
            size_of_image,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );

        if (image_base == nullptr) {
            return loader_errc::allocation_failed;
        }

        base_address_ = image_base;
        image_size_ = size_of_image;

        const std::size_t header_copy_bytes = (std::min)(size_of_headers, raw_bytes.size());
        std::memcpy(image_base, raw_bytes.data(), header_copy_bytes);

        const auto* section_header = IMAGE_FIRST_SECTION(nt_headers);
        std::uint32_t sections_mapped = 0;

        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section_header) {
            if (section_header->SizeOfRawData == 0) {
                continue;
            }

            void* dest_section = rva_to_ptr(section_header->VirtualAddress);
            const void* src_section = raw_bytes.data() + section_header->PointerToRawData;

            if (section_header->PointerToRawData + section_header->SizeOfRawData <= raw_bytes.size()) {
                std::memcpy(dest_section, src_section, section_header->SizeOfRawData);
                sections_mapped++;
            }
        }

        out_result.base_address = image_base;
        out_result.image_size = size_of_image;
        out_result.sections_mapped = sections_mapped;
        return loader_errc::success;
    }

    std::error_code pe_image::apply_relocations(
        const IMAGE_NT_HEADERS64* nt_headers,
        load_result& out_result
    ) noexcept {
        const std::uintptr_t delta = reinterpret_cast<std::uintptr_t>(base_address_) - nt_headers->OptionalHeader.ImageBase;
        std::uint32_t relocations_applied = 0;

        const auto* reloc_dir = get_directory_entry(nt_headers, IMAGE_DIRECTORY_ENTRY_BASERELOC);
        if (delta != 0 && reloc_dir != nullptr) {
            auto* current_block = rva_to_ptr<IMAGE_BASE_RELOCATION>(reloc_dir->VirtualAddress);
            const auto* reloc_end = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<const std::uint8_t*>(current_block) + reloc_dir->Size
            );

            while (current_block < reloc_end && current_block->SizeOfBlock > 0) {
                const std::uint32_t entry_count = (current_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                const auto* entries = reinterpret_cast<const WORD*>(current_block + 1);

                for (std::uint32_t i = 0; i < entry_count; ++i) {
                    const WORD entry = entries[i];
                    const WORD type = entry >> 12;
                    const WORD offset = entry & 0x0FFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        auto* patch_address = rva_to_ptr<std::uint64_t>(current_block->VirtualAddress + offset);
                        *patch_address += delta;
                        relocations_applied++;
                    }
                }

                current_block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                    reinterpret_cast<std::uint8_t*>(current_block) + current_block->SizeOfBlock
                );
            }
        }

        out_result.relocations_applied = relocations_applied;
        return loader_errc::success;
    }

    std::error_code pe_image::resolve_imports(
        const IMAGE_NT_HEADERS64* nt_headers,
        load_result& out_result
    ) noexcept {
        std::uint32_t imports_resolved = 0;
        const auto* import_dir = get_directory_entry(nt_headers, IMAGE_DIRECTORY_ENTRY_IMPORT);

        if (import_dir != nullptr) {
            auto* import_desc = rva_to_ptr<IMAGE_IMPORT_DESCRIPTOR>(import_dir->VirtualAddress);

            while (import_desc->Name != 0) {
                const char* module_name = rva_to_ptr<const char>(import_desc->Name);
                HMODULE h_module = LoadLibraryA(module_name);
                if (h_module == nullptr) {
                    return loader_errc::import_resolution_failed;
                }

                const std::uint32_t thunk_rva = import_desc->OriginalFirstThunk != 0 
                    ? import_desc->OriginalFirstThunk 
                    : import_desc->FirstThunk;

                auto* thunk_data = rva_to_ptr<IMAGE_THUNK_DATA64>(thunk_rva);
                auto* iat_data = rva_to_ptr<IMAGE_THUNK_DATA64>(import_desc->FirstThunk);

                while (thunk_data->u1.AddressOfData != 0) {
                    FARPROC func_addr = nullptr;

                    if (IMAGE_SNAP_BY_ORDINAL64(thunk_data->u1.Ordinal)) {
                        func_addr = GetProcAddress(h_module, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(thunk_data->u1.Ordinal)));
                    } else {
                        const auto* import_by_name = rva_to_ptr<const IMAGE_IMPORT_BY_NAME>(thunk_data->u1.AddressOfData);
                        func_addr = GetProcAddress(h_module, import_by_name->Name);
                    }

                    if (func_addr == nullptr) {
                        return loader_errc::import_resolution_failed;
                    }

                    iat_data->u1.Function = reinterpret_cast<std::uintptr_t>(func_addr);
                    imports_resolved++;

                    thunk_data++;
                    iat_data++;
                }

                import_desc++;
            }
        }

        out_result.imports_resolved = imports_resolved;
        return loader_errc::success;
    }

    void pe_image::execute_tls_callbacks(
        const IMAGE_NT_HEADERS64* nt_headers,
        load_result& out_result
    ) noexcept {
        std::uint32_t tls_callbacks_invoked = 0;
        const auto* tls_dir = get_directory_entry(nt_headers, IMAGE_DIRECTORY_ENTRY_TLS);

        if (tls_dir != nullptr) {
            const auto* tls_directory = rva_to_ptr<const IMAGE_TLS_DIRECTORY64>(tls_dir->VirtualAddress);

            if (tls_directory->AddressOfCallBacks != 0) {
                auto* callbacks = *reinterpret_cast<PIMAGE_TLS_CALLBACK**>(
                    const_cast<ULONGLONG*>(&tls_directory->AddressOfCallBacks)
                );

                while (callbacks != nullptr && *callbacks != nullptr) {
                    (*callbacks)(base_address_, DLL_PROCESS_ATTACH, nullptr);
                    tls_callbacks_invoked++;
                    callbacks++;
                }
            }
        }

        out_result.tls_callbacks_invoked = tls_callbacks_invoked;
    }

    void pe_image::register_exception_table(
        const IMAGE_NT_HEADERS64* nt_headers,
        load_result& out_result
    ) noexcept {
        bool seh_registered = false;
        const auto* exception_dir = get_directory_entry(nt_headers, IMAGE_DIRECTORY_ENTRY_EXCEPTION);

        if (exception_dir != nullptr) {
            pdata_table_ = rva_to_ptr<IMAGE_RUNTIME_FUNCTION_ENTRY>(exception_dir->VirtualAddress);
            pdata_entries_ = exception_dir->Size / sizeof(RUNTIME_FUNCTION);

            if (pdata_entries_ > 0) {
                seh_registered = RtlAddFunctionTable(
                    pdata_table_,
                    pdata_entries_,
                    reinterpret_cast<DWORD64>(base_address_)
                );
                seh_registered_ = seh_registered;
            }
        }

        out_result.seh_registered = seh_registered;
    }

    void pe_image::prepare_entry_point(
        const IMAGE_NT_HEADERS64* nt_headers,
        load_result& out_result
    ) noexcept {
        if (nt_headers->OptionalHeader.AddressOfEntryPoint != 0) {
            entry_point_ = reinterpret_cast<std::uintptr_t>(
                rva_to_ptr(nt_headers->OptionalHeader.AddressOfEntryPoint)
            );
        }
        out_result.entry_point = entry_point_;
    }

    std::error_code pe_image::map_from_buffer(std::span<const std::uint8_t> raw_bytes, load_result& out_result) {
        cleanup();

        const IMAGE_NT_HEADERS64* nt_headers = nullptr;

        if (auto ec = validate_headers(raw_bytes, nt_headers); ec) {
            return ec;
        }

        if (auto ec = allocate_and_map_sections(raw_bytes, nt_headers, out_result); ec) {
            return ec;
        }

        if (auto ec = apply_relocations(nt_headers, out_result); ec) {
            return ec;
        }

        if (auto ec = resolve_imports(nt_headers, out_result); ec) {
            return ec;
        }

        execute_tls_callbacks(nt_headers, out_result);
        register_exception_table(nt_headers, out_result);
        prepare_entry_point(nt_headers, out_result);

        return loader_errc::success;
    }

    bool pe_image::execute_entry_point(DWORD reason, LPVOID reserved) {
        if (entry_point_ == 0) {
            return false;
        }

        using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto dll_main = reinterpret_cast<DllMain_t>(entry_point_);

        return dll_main(reinterpret_cast<HINSTANCE>(base_address_), reason, reserved) == TRUE;
    }

} // namespace inmemory_pe
