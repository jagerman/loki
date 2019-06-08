#include <string>
#include <iostream>
#include "cryptonote_basic/cryptonote_basic.h"
#include "file_io_utils.h"
#include "string_tools.h"
#include "wipeable_string.h"

int usage(std::string msg) {
    std::cerr << msg << "\n\nUsage: generate-service-key [PREFIX] -- generates a new service node key start with PREFIX and stores it in a file named PUBKEY\n\n";
    return 1;
}

int main(int argc, char *argv[]) {
    el::Loggers::addFlag(el::LoggingFlag::HierarchicalLogging);

    std::string prefix;
    if (argc == 2) {
        prefix = std::string(argv[1]);
        for (char c : prefix)
            if (!((c >= '0' && c <= '9') or (c >= 'a' && c <= 'f')))
                return usage("PREFIX invalid");
    }
    else if (argc != 1)
        return usage("Bad arguments!");

    uint64_t expected = 1;
    for (size_t i = 0; i < prefix.size(); i++)
        expected *= 16;

    std::cout << "Looking for a key starting with " << prefix << "; this will take (on average) " << expected << " tries\n";

    auto &dev = hw::get_device("default");
    for (uint64_t i = 1;; i++) {
        auto keypair = cryptonote::keypair::generate(dev);
        auto hex_pub = epee::string_tools::pod_to_hex(keypair.pub);
        if (!std::equal(prefix.begin(), prefix.end(), hex_pub.begin())) {
            if (i % 100000 == 0) std::cout << "Still trying after " << i << " attempts (" << (i*100 / expected) << "% effort)\n";
            continue;
        }
        std::cout << "Found one (" << hex_pub << ") after " << i << " attempts (" << (i * 100 / expected) << "% effort)\n";
        if (epee::file_io_utils::is_file_exist(hex_pub))
            return usage("Error: " + hex_pub + " already exists");

        std::string keystr(reinterpret_cast<const char *>(&keypair.sec), sizeof(keypair.sec));
        bool r = epee::file_io_utils::save_string_to_file(hex_pub, keystr);
        epee::wipeable_string wipe(keystr);
        CHECK_AND_ASSERT_MES(r, false, "failed to save service node key to file");

        boost::filesystem::permissions(hex_pub, boost::filesystem::owner_read);

        std::cout << "Generated and saved private service key to file " << hex_pub << ".\n\n";
        return 0;
    }
}
