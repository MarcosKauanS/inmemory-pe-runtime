#include <inmemory_pe/loader.hpp>
#include <iostream>
#include <fstream>
#include <vector>
#include <format>

namespace {
    std::vector<std::uint8_t> read_binary_file(const std::string& path, std::error_code& ec) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            ec = std::make_error_code(std::errc::no_such_file_or_directory);
            return {};
        }

        const auto file_size = file.tellg();
        if (file_size <= 0) {
            ec = std::make_error_code(std::errc::io_error);
            return {};
        }

        std::vector<std::uint8_t> buffer(static_cast<std::size_t>(file_size));
        file.seekg(0, std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
            ec = std::make_error_code(std::errc::io_error);
            return {};
        }

        ec.clear();
        return buffer;
    }
} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << std::format("Usage: {} <path_to_x64_dll>\n", argv[0]);
        std::cerr << std::format("Example: {} sample_payload.dll\n", argv[0]);
        return 1;
    }

    const std::string payload_path = argv[1];
    std::cout << std::format("[*] Reading binary payload: {}\n", payload_path);

    std::error_code ec;
    const auto raw_payload = read_binary_file(payload_path, ec);

    if (ec) {
        std::cerr << std::format("[-] Read error: {}\n", ec.message());
        return 1;
    }

    std::cout << std::format("[+] Ingested {} bytes into memory\n", raw_payload.size());
    std::cout << "[*] Executing manual mapping pipeline:\n";

    inmemory_pe::pe_image mapped_image;
    inmemory_pe::load_result result{};

    ec = mapped_image.map_from_buffer(raw_payload, result);
    if (ec) {
        std::cerr << std::format("[-] Mapping failed: {}\n", ec.message());
        return 1;
    }

    std::cout << "    [1] PE Headers: AMD64 (x64) verified\n";
    std::cout << std::format("    [2] VirtualAlloc: 0x{:X} bytes committed at {}\n", result.image_size, result.base_address);
    std::cout << std::format("        -> Mapped {} virtual sections\n", result.sections_mapped);
    std::cout << std::format("    [3] Base Relocations: {} entries patched via DIR64\n", result.relocations_applied);
    std::cout << std::format("    [4] IAT Resolution: {} imports bound\n", result.imports_resolved);
    std::cout << std::format("    [5] TLS Callbacks: {} executed\n", result.tls_callbacks_invoked);
    std::cout << std::format("    [6] SEH Unwinding: {}\n", result.seh_registered ? "Registered via RtlAddFunctionTable" : "Skipped (no .pdata)");
    std::cout << std::format("    [7] EntryPoint: 0x{:X}\n\n", result.entry_point);

    std::cout << "[*] Invoking module entry point (DLL_PROCESS_ATTACH)\n";

    const bool exec_ok = mapped_image.execute_entry_point(DLL_PROCESS_ATTACH, nullptr);

    if (exec_ok) {
        std::cout << "[+] Entry point executed successfully (returned TRUE)\n";
        std::cout << "[+] In-memory execution completed without disk artifacts\n";
    } else {
        std::cerr << "[-] Entry point execution failed\n";
        return 1;
    }

    return 0;
}
