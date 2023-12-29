// Documentation: https://developers.elliptic.co/docs/authentication
#include <iomanip>
#include <iostream>
#include <string>

// libsecp256k1
#include "src/hash_impl.h"

void sign(const std::string &api_key,
          long unsigned time_of_request,
          const std::string &http_method,
          const std::string &http_path,
          const std::string &body)
{
    secp256k1_hmac_sha256 hasher;
    secp256k1_hmac_sha256_initialize(
        &hasher, (const unsigned char *)api_key.data(), api_key.size());

    const std::string request = std::to_string(time_of_request) + http_method + http_path + body;
    std::cout << "Request is:\n" << request << std::endl;

    unsigned char out[32];
    secp256k1_hmac_sha256_write(&hasher, (const unsigned char *)request.data(), request.size());
    secp256k1_hmac_sha256_finalize(&hasher, out);

    std::cout << "Signature is:\n";
    std::cout << std::hex << std::setw(2) << std::setfill('0');
    for (const auto &c : out)
        std::cout << static_cast<unsigned int>(c);
    std::cout << "\n" << std::endl;
}

int main()
{
    // Elliptic API Key (hex format)
    // base64: 894f142d667e8cdaca6822ac173937af
    // hex: f3de1fd78d9debaedef1c75a71aebcdb669cd7bdfddfb69f
    const std::string api_key =
        "\xf3\xde\x1f\xd7\x8d\x9d\xeb\xae\xde\xf1\xc7\x5a\x71\xae\xbc\xdb\x66\x9c"
        "\xd7\xbd\xfd\xdf\xb6\x9f";

    const auto time_of_request = 1478692862000ul;
    const std::string payload =
        R"([{"customer_reference":"123456","subject":{"asset":"BTC",)"
        R"("hash":"accf5c09cc027339a3beb2e28104ce9f406ecbbd29775b4a1a17ba213f1e035e",)"
        R"("output_address":"15Hm2UEPaEuiAmgyNgd5mF3wugqLsYs3Wn","output_type":"address",)"
        R"("type":"transaction"},"type":"source_of_funds"}])";

    // base64: 65mQHB2o95lL3I+N/bZYwDC9p2YvNwsVDnXr8u72hUk=
    // hex: eb99901c1da8f7994bdc8f8dfdb658c030bda7662f370b150e75ebf2eef68549
    sign(api_key, time_of_request, "POST", "/v2/analyses", payload);

    // base64: cN9fRUqeT7UnwwpkBZaNmnwxKAPHkhytdXelfUVvxMI=
    // hex: 70df5f454a9e4fb527c30a6405968d9a7c312803c7921cad7577a57d456fc4c2
    sign(api_key, time_of_request, "GET", "/v2/customers", "{}");
}