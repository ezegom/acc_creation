//
// Created by parallels on 7/20/17.
//

#ifndef ACCOUNTS_PUBLICKEYS_H
#define ACCOUNTS_PUBLICKEYS_H


#include "SecretKeys.h"
#include <string>
/*
 * TODO: What if someone wants to generate multiple addresses? This must be handled by wallet
 * TODO: generateKeys can't overwrite previous keys, as the sk->pk relationship could be lost.
 *  - Scenario : Generate secret keys, then call public keys with bad values.
 *      - Wallet must take care of this
 *
 * TODO: Wallets must have "CreatePrivateAccount" that stores pub/priv key pairs with naming acc_skEnc acc_pkEnc acc_pkAddr acc_skAddr
 */
template<typename T>
static std::string HexStr(const T itbegin, const T itend);


class PublicKeys {
private:
    std::string accName;
    uint256 addrPk;
    uint256 encPk;
    uint256 generatePkEnc(const uint256 &);
    uint256 generatePkAddr(const uint252 &);
    std::string toHexString() const;
    void storeKeys(); //called only by generateKeys


public:
    PublicKeys(std::string acc): accName(acc), addrPk(uint256()), encPk(uint256()){};
    void generateKeys(SecretKeys&);
    void paymentAddress() const; //Outputs the payment address

};


#endif //ACCOUNTS_PUBLICKEYS_H
