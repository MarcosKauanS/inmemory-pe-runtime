#pragma once

#include <cstdint>
#include <span>
#include <system_error>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace inmemory_pe {

    enum class loader_errc {
        success = 0,
        invalid_dos_header,
        invalid_nt_signature,
        unsupported_architecture,
        allocation_failed,
        relocation_failed,
        import_resolution_failed,
        tls_execution_failed,
        exception_registration_failed,
        entry_point_failed
    };

    const std::error_category& loader_category() noexcept;

    inline std::error_code make_error_code(loader_errc e) noexcept {
        return { static_cast<int>(e), loader_category() };
    }

    struct load_result {
        void* base_address{ nullptr };
        std::size_t image_size{ 0 };
        std::uintptr_t entry_point{ 0 };
        std::uint32_t sections_mapped{ 0 };
        std::uint32_t relocations_applied{ 0 };
        std::uint32_t imports_resolved{ 0 };
        std::uint32_t tls_callbacks_invoked{ 0 };
        bool seh_registered{ false };
    };

    class pe_image {
    public:
        pe_image() noexcept = default;
        ~pe_image() noexcept;

        pe_image(const pe_image&) = delete;
        pe_image& operator=(const pe_image&) = delete;

        pe_image(pe_image&& other) noexcept;
        pe_image& operator=(pe_image&& other) noexcept;

        void swap(pe_image& other) noexcept;

        std::error_code map_from_buffer(std::span<const std::uint8_t> raw_bytes, load_result& out_result);

        bool execute_entry_point(DWORD reason = DLL_PROCESS_ATTACH, LPVOID reserved = nullptr);

        [[nodiscard]] void* get_base() const noexcept { return base_address_; }
        [[nodiscard]] std::size_t get_size() const noexcept { return image_size_; }

    private:
        void* base_address_{ nullptr };
        std::size_t image_size_{ 0 };
        std::uintptr_t entry_point_{ 0 };
        bool seh_registered_{ false };
        PRUNTIME_FUNCTION pdata_table_{ nullptr };
        DWORD pdata_entries_{ 0 };

        template <typename T = void>
        [[nodiscard]] T* rva_to_ptr(std::uintptr_t rva) const noexcept {
            if (base_address_ == nullptr || rva == 0) {
                return nullptr;
            }
            return reinterpret_cast<T*>(static_cast<std::uint8_t*>(base_address_) + rva);
        }

        [[nodiscard]] static const IMAGE_DATA_DIRECTORY* get_directory_entry(
            const IMAGE_NT_HEADERS64* nt_headers,
            std::size_t directory_index
        ) noexcept {
            if (nt_headers == nullptr || directory_index >= nt_headers->OptionalHeader.NumberOfRvaAndSizes) {
                return nullptr;
            }
            const auto& dir = nt_headers->OptionalHeader.DataDirectory[directory_index];
            if (dir.VirtualAddress == 0 || dir.Size == 0) {
                return nullptr;
            }
            return &dir;
        }

        std::error_code validate_headers(std::span<const std::uint8_t> raw_bytes, const IMAGE_NT_HEADERS64*& out_nt_headers) const noexcept;
        std::error_code allocate_and_map_sections(std::span<const std::uint8_t> raw_bytes, const IMAGE_NT_HEADERS64* nt_headers, load_result& out_result) noexcept;
        std::error_code apply_relocations(const IMAGE_NT_HEADERS64* nt_headers, load_result& out_result) noexcept;
        std::error_code resolve_imports(const IMAGE_NT_HEADERS64* nt_headers, load_result& out_result) noexcept;
        void execute_tls_callbacks(const IMAGE_NT_HEADERS64* nt_headers, load_result& out_result) noexcept;
        void register_exception_table(const IMAGE_NT_HEADERS64* nt_headers, load_result& out_result) noexcept;
        void prepare_entry_point(const IMAGE_NT_HEADERS64* nt_headers, load_result& out_result) noexcept;

        void cleanup() noexcept;
    };

    inline void swap(pe_image& lhs, pe_image& rhs) noexcept {
        lhs.swap(rhs);
    }

} // namespace inmemory_pe

namespace std {
    template <>
    struct is_error_code_enum<inmemory_pe::loader_errc> : true_type {};
}
