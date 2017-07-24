

#ifndef ACCOUNTS_PRIVATEKEYS_H
#define ACCOUNTS_PRIVATEKEYS_H

#include "uint252.h"
#include "prf.h"

template<typename T>
static std::string HexStr(const T itbegin, const T itend);

class SecretKeys {
private:
    std::string accName;
    uint252 random252();
    uint256 encSecretKey();
    void storeKeys() const;
    std::string toHexString() const;

public:
    SecretKeys(std::string _accName) : accName(_accName), addrSk(uint252()) , encSk(uint256()) {}
    void generateKeys();

    uint252 addrSk;
    uint256 encSk;

};


#endif //ACCOUNTS_PRIVATEKEYS_H
