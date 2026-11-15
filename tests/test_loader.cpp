#include <gtest/gtest.h>
#include <inmemory_pe/loader.hpp>

#include <fstream>
#include <vector>

namespace {

    [[nodiscard]] std::vector<std::uint8_t> read_file_bytes(const char* path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return {};
        }

        const auto size = file.tellg();
        if (size <= 0) {
            return {};
        }

        std::vector<std::uint8_t> buffer(static_cast<std::size_t>(size));
        file.seekg(0, std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            return {};
        }
        return buffer;
    }

    struct minimal_pe_builder {
        std::vector<std::uint8_t> buffer;

        minimal_pe_builder()
            : buffer(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64), 0) {
            auto* d = dos();
            d->e_magic = IMAGE_DOS_SIGNATURE;
            d->e_lfanew = static_cast<LONG>(sizeof(IMAGE_DOS_HEADER));

            auto* n = nt();
            n->Signature = IMAGE_NT_SIGNATURE;
            n->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
            n->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            n->OptionalHeader.SizeOfImage = 0x1000;
            n->OptionalHeader.SizeOfHeaders = static_cast<DWORD>(buffer.size());
        }

        [[nodiscard]] IMAGE_DOS_HEADER* dos() noexcept {
            return reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
        }

        [[nodiscard]] IMAGE_NT_HEADERS64* nt() noexcept {
            return reinterpret_cast<IMAGE_NT_HEADERS64*>(buffer.data() + sizeof(IMAGE_DOS_HEADER));
        }
    };

} // namespace

TEST(LoaderValidationTest, RejectsEmptyBuffer) {
    inmemory_pe::pe_image image;
    inmemory_pe::load_result result{};

    const auto ec = image.map_from_buffer({}, result);
    EXPECT_EQ(ec, inmemory_pe::make_error_code(inmemory_pe::loader_errc::invalid_dos_header));
    EXPECT_EQ(image.get_base(), nullptr);
}

TEST(LoaderValidationTest, RejectsInvalidDosMagic) {
    minimal_pe_builder pe;
    pe.dos()->e_magic = 0x0000;

    inmemory_pe::pe_image image;
    inmemory_pe::load_result result{};
    const auto ec = image.map_from_buffer(pe.buffer, result);
    EXPECT_EQ(ec, inmemory_pe::make_error_code(inmemory_pe::loader_errc::invalid_dos_header));
    EXPECT_EQ(image.get_base(), nullptr);
}

TEST(LoaderValidationTest, RejectsInvalidNtSignature) {
    minimal_pe_builder pe;
    pe.nt()->Signature = 0xDEADBEEF;

    inmemory_pe::pe_image image;
    inmemory_pe::load_result result{};
    const auto ec = image.map_from_buffer(pe.buffer, result);
    EXPECT_EQ(ec, inmemory_pe::make_error_code(inmemory_pe::loader_errc::invalid_nt_signature));
    EXPECT_EQ(image.get_base(), nullptr);
}

TEST(LoaderValidationTest, RejectsOutOfBoundsLfanew) {
    minimal_pe_builder pe;
    pe.dos()->e_lfanew = 0x7FFFFFFF;

    inmemory_pe::pe_image image;
    inmemory_pe::load_result result{};
    const auto ec = image.map_from_buffer(pe.buffer, result);
    EXPECT_EQ(ec, inmemory_pe::make_error_code(inmemory_pe::loader_errc::invalid_nt_signature));
    EXPECT_EQ(image.get_base(), nullptr);
}

TEST(LoaderValidationTest, RejectsUnsupportedArchitecture) {
    minimal_pe_builder pe;
    pe.nt()->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;

    inmemory_pe::pe_image image;
    inmemory_pe::load_result result{};
    const auto ec = image.map_from_buffer(pe.buffer, result);
    EXPECT_EQ(ec, inmemory_pe::make_error_code(inmemory_pe::loader_errc::unsupported_architecture));
    EXPECT_EQ(image.get_base(), nullptr);
}

TEST(LoaderValidationTest, RejectsUnallocatableImageSize) {
    minimal_pe_builder pe;
    pe.nt()->OptionalHeader.SizeOfImage = 0;

    inmemory_pe::pe_image image;
    inmemory_pe::load_result result{};
    const auto ec = image.map_from_buffer(pe.buffer, result);
    EXPECT_EQ(ec, inmemory_pe::make_error_code(inmemory_pe::loader_errc::allocation_failed));
    EXPECT_EQ(image.get_base(), nullptr);
}

TEST(LoaderIntegrationTest, MapsAndExecutesTestPayload) {
    const auto bytes = read_file_bytes(TEST_PAYLOAD_PATH);
    ASSERT_FALSE(bytes.empty()) << "Failed to read test_payload.dll at " << TEST_PAYLOAD_PATH;

    inmemory_pe::pe_image image;
    inmemory_pe::load_result result{};
    const auto ec = image.map_from_buffer(bytes, result);

    ASSERT_FALSE(ec) << ec.message();
    EXPECT_NE(result.base_address, nullptr);
    EXPECT_GT(result.image_size, 0u);
    EXPECT_GT(result.sections_mapped, 0u);
    EXPECT_GT(result.imports_resolved, 0u);
    EXPECT_GT(result.tls_callbacks_invoked, 0u);
    EXPECT_TRUE(result.seh_registered);
    EXPECT_TRUE(image.execute_entry_point(DLL_PROCESS_ATTACH, nullptr));
}

TEST(LoaderLifecycleTest, ExecuteEntryPointFailsWhenUnmapped) {
    inmemory_pe::pe_image image;
    EXPECT_FALSE(image.execute_entry_point(DLL_PROCESS_ATTACH, nullptr));
}

TEST(LoaderLifecycleTest, MoveSemanticsTransferOwnership) {
    const auto bytes = read_file_bytes(TEST_PAYLOAD_PATH);
    ASSERT_FALSE(bytes.empty());

    inmemory_pe::pe_image source;
    inmemory_pe::load_result result{};
    ASSERT_FALSE(source.map_from_buffer(bytes, result));
    void* original_base = source.get_base();
    ASSERT_NE(original_base, nullptr);

    inmemory_pe::pe_image moved(std::move(source));
    EXPECT_EQ(source.get_base(), nullptr);
    EXPECT_EQ(moved.get_base(), original_base);
}
