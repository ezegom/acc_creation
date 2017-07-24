#include <iostream>
#include <sodium.h>
#include "uint256.h"
#include "SecretKeys.h"
#include "PublicKeys.h"


int main() {
    if (sodium_init() == -1 ){
        throw std::runtime_error("Sodium init failed");
    }

    std::string name = "acc1";

    SecretKeys sks(name);
    sks.generateKeys();

    PublicKeys pks(name);
    pks.generateKeys(sks);

    return 0;
}
