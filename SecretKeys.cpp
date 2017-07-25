#include "SecretKeys.h"
#include <sodium.h>
#include <iostream>
#include <fstream>

/*
 * TODO: Best place to define this function.
 */
template<typename T>
static std::string HexStr(const T itbegin, const T itend)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return rv;
}

/*
 * Creates the Address Secret key. Uses Sodium's randombytes_buf to generate 32 random bytes.
 * Since key is 252 bits, clears the most significant 4 bits and returns a uint252
 */
uint252 SecretKeys::random252() {
    uint256 a_sk;
    randombytes_buf(a_sk.begin(),32);
    (*a_sk.begin()) &= 0x0F;
    return uint252(a_sk);
}
/*
 * Creates encryption secret key for the Elliptic Curve Diffie-Hellman Key Exchange
 * The encryption secret key is derived from the Address Secret Key.
 *  Uses PRF (SHA256) with the address secret key.
 */

uint256 SecretKeys::encSecretKey() {
    auto sk_enc = PRF_addr_sk_enc(this->addrSk);
/* [Bern2006] https://cr.yp.to/ecdh/curve25519-20060209.pdf
 * uses this as an example, but what is it used for?.
    sk_enc.begin()[0] &= 248;
    sk_enc.begin()[31] &= 127;
    sk_enc.begin()[31] |= 64;
*/
    return sk_enc;
}
/*
 * Public function:
 *  Once called generates the address and encryption secret keys and stores them both in a .priv file.
 *  Call this function from wallet to generate the private keys.
 *  Note: This function must be called before the public key generation function.
 *  TODO: Check if account name already exists before overwriting previous .priv files.
 */
void SecretKeys::generateKeys() {
    this->addrSk = random252();
    this->encSk = encSecretKey();
    storeKeys();
}
/*
 * Returns a string with the hexadecimal of the address secret key and encryption secret key. Separated by a space.
 */
std::string SecretKeys::toHexString() const{
    std::string aSkHex = HexStr(this->addrSk.begin(),this->addrSk.end());
    std::string encSkHex = HexStr(this->encSk.begin(), this->encSk.end());
    std::string temp = aSkHex;
    temp.append(" ");
    temp.append(encSkHex);
    std::cout<<"Private keys"<<std::endl;
    std::cout<<temp<<std::endl;
    return temp;
}

/*
 * TODO: Before saving file check if account name already exists. Don't want to replace already existing files.
 */
void SecretKeys::storeKeys() const{
    std::ofstream privKeys(accName+".priv");
    privKeys << toHexString();
    privKeys.close();
}