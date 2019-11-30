#include <string>
#include <iostream>
#include "quorumnet/sn_network.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "file_io_utils.h"
#include "wipeable_string.h"

int usage(std::string msg) {
    std::cerr << msg << "\n\nUsage: generate-service-key [PREFIX] -- generates a new service node key optionally with pubkey starting with hex PREFIX and stores it in a file named PUBKEY";
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc > 2 || (argc == 2 && argv[1][0] == '-'))
        return usage("bad args");
    std::string prefix;
    if (argc == 2)
        prefix = argv[1];

    using cryptonote::keypair;
    std::string keystr, hex;
    size_t count = 0;
    size_t expected = 1;
    for (unsigned i = 0; i < prefix.size(); i++) expected *= 16;
    std::cout << "Looking for a key with prefix '" << prefix << "'; this will take an average of " << expected << " attempts\n";
    while (true) {
        count++;
        keypair kp = keypair::generate(hw::get_device("default"));
        keystr = std::string(reinterpret_cast<const char *>(&kp.sec), sizeof(kp.sec));

        hex = quorumnet::as_hex(kp.pub.data, kp.pub.data + 32);
        if (prefix.empty() || hex.substr(0, prefix.size()) == prefix)
            break;
        if (count % 10000 == 0)
            std::cout << "Still searching for " << prefix << ", generated " << count << " keypairs\n";
    }
    std::cout << "Found pubkey " << hex << " after " << count << " attempts (" << count*100./expected << "% of avg.)\n";
    bool r = epee::file_io_utils::save_string_to_file(hex, keystr);
    CHECK_AND_ASSERT_MES(r, 1, "failed to save service node key to file");

    std::cout << "Saved key to " << hex << "\n";

    using namespace boost::filesystem;
    permissions(hex, owner_read);
}
