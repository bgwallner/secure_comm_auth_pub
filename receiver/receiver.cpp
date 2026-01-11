// C system headers
#include <mqueue.h>

// C++ standard library headers
#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <thread>

// Third-party (Botan) headers
#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/mac.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>
#include <botan/pem.h>

// Project headers
#include "common.hpp"

// Private key for signing (PEM format)
const std::string kReceiverPrivateKeyPem = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCGRode4Mqvw3aC
UzG1NFRioJ1HpyMWC1uvaSKmasOxwG13+8rNGB9BZCWvnloB15UZ3RA8R1IG5tdG
o2Nh6DW98dYyPSWr1lGk+uGTmA78XhMrFP8AUbes/fC9LXfyxty0rhijJFv7J6Dk
zDd2yCI14/4vopsMNyED4J3HwySh/FYrNbvgZ1HwuUxlg8UUpW7adozBHtL67jQp
TC944a1tiQ0ET9esOPJXVJvHSYE8twC5el6z0qiy9hj7BNclobiBvWphrx3GZ/We
eyh3rtmbAQ67xEg6MX2ljY/+Gp57wNxw1Ji0ARqnwWl5lmYNozNquRAfD92V30jM
yMPTIyW1AgMBAAECggEAFKubT70BnrSTlATsGEXFvsgUZjEhytU1SEfCRIWXeg/S
GkAZ7GAsAZRB4+rX1sRB6PEZvHnLNBJJrg9db3dAfKzTqTi2CaGswF25p4+nMOzn
fQCWr80knh4advjep/I6jBrn4odonH1xfH8+g4vUDmE6YklhHmyHKdJkX5nYFBJr
9p/fDj2ctQJNL37G7rOTFieBBoWdG3w9Hotc8HNX3nY+iyOtzHcGZkw8tEdjHcij
YlUr2KXBSkofxzMtNNzu5GWAFU5OEVqVcUgqNy+TuEZKbM1LwjiwSGXQib1RlUjr
FGSQYoE2Z6FgUIGOrSHRcEFws89aOYaibZn5hSRHgQKBgQC867L7H7DrWoNpS3ag
zEdI9zUgK1HZtQ+6YweTwq6soo8kHKuTkhHpEk6ybMI5uM3B4pb4EhJq9B6SWOoN
pv3CFjaGnso0A0tXFO90udu1q9aHU+BPjtWwRf1QmO0zJxAtBPyBavvri1XbD04D
ZTx/ubXEDdMLIo3LcjdnsAL/NQKBgQC188CMdxVRBX3QOmLY0Y5yrcHArTSVA7vJ
IiGuJRe18tFv1Pqs1T7POrEsHuOVNWUgl+gY1/lsxSsylWsbZ04H21mb34HSR7Q2
qAFj94hGQEbCedtKqUd6F0zHFekByB6+2puYw8ZTnD0SMiGvJtTNJzfWM448ec4e
gM3C8/PcgQKBgBs9uV8woKgvMwe50+83xYel7ckntfO4gf4UTYFm7x0Bi7ZfU/ZB
d8et1h8wQ4ljNnggnjhDEtjNPqNHoug5DhowbchXmTyKxRBXenfQXPgDQTneRFf0
dqemT/KROpLHrTNwpqBattyuCME/obYnoOOh+a29eJMAdoXBgG+5F5WJAoGBAIhK
7QmKzhHhvitzAMYOuthWJZMxavjQUiLIiVgL+uXU3GMbsyYxmhnaigpVnP4QgA7Z
Gwc5CGIck04RtKhTSpUCDu5+jp04Dtr+IASEz7Rnw1k7tDMJ+DuRJnbeh6pJABbQ
Y8sbovzQRMLTgH3V5YNDBEVUWxAb4XTh4L9Ow3WBAoGAOEoy77AHtEAKd9OpxezM
L6Eek1JVb+mxLA+z5YivDECxg8ZloXhy1b/w17kxXfB+o3iZzDyvPoFWgvhwjegO
Ng2a3KoH7+WGqYPOyaiogS9SYhcX9TUct/zpiJ5fIl2rb+mwy3kaq0R6McFgmxWl
CVgBWb9kmCzbuAG5oB0pt98=
-----END PRIVATE KEY-----)";

// Pre-shared public key for verifying signatures (PEM format)
const std::string kSenderPublicKeyPem = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvjGZwFB0aHgd9kxZzydj
uFQEdqAhb2NXvx0PAKvCMse+zwd2SJ8VHMv2Tzimso+/GQmkCScdy0wPG38JHW5s
FVnGdFTKYi7OABRD2p9EE33ebVJXYvNjBXF6otTW6jqaQbn2mFHKWXDUSjBcz5z2
bZ13DtaVTp0e6VB2j58UPbV8OJID1ZdzvaOQi7m8JYrpj7XZ+1Ab5osB3384PWWG
hjzp4WpvGdiir+KiPziREBPTxYPPfT4BSQ/s0e7xmt9Qm22aHmAdY1uHaqwskWlz
sbT3gNAHCsq8UUy6zp+XGh6cG8eI4jTX8eV2j7DP92ReS+A61rnMlwmw8GwAV65t
awIDAQAB
-----END PUBLIC KEY-----)";


void print_buffer_hex(const std::array<std::byte, kMessageSize>& buffer, size_t received_bytes) {
    std::cout << "[Receiver] 0x";
    for (size_t i = 0; i < received_bytes; ++i) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(buffer[i]);
    }
    std::cout << std::dec;  // reset to decimal
    std::cout << "\n";
}

void print_vector_hex(const std::vector<uint8_t>& vec) {
    std::cout << "[Receiver] 0x";
    for (const auto& byte : vec) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(byte);
    }
    std::cout << std::dec;  // reset to decimal
    std::cout << "\n";
}

void print_vector_hex_n(const std::vector<uint8_t>& vec, size_t n = 64) {
    std::cout << "[Receiver] 0x";
    if (vec.size() <= 2 * n) {
        for (const auto& byte : vec) {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned int>(byte);
        }
    } else {
        for (size_t i = 0; i < n; ++i) {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned int>(vec[i]);
        }
        std::cout << " ... ";
        for (size_t i = vec.size() - n; i < vec.size(); ++i) {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned int>(vec[i]);
        }
    }
    std::cout << std::dec;  // reset to decimal
    std::cout << "\n";
}

void print_botan_secure_hex(const Botan::secure_vector<uint8_t>& vec) {
    std::cout << "[Receiver] 0x";
    for (const auto& byte : vec) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(byte);
    }
    std::cout << std::dec;  // reset to decimal
    std::cout << "\n";
}

int get_public_key(mqd_t mq, std::unique_ptr<Botan::Public_Key>& public_key)
{
    std::vector<uint8_t> pub_key_buffer(kMessageSize);

    const ssize_t received_bytes =
        mq_receive(mq,
                   reinterpret_cast<char*>(pub_key_buffer.data()),
                   pub_key_buffer.size(),
                   nullptr);

    if (received_bytes == -1) {
        perror("mq_receive");
        return kNOT_OK;
    }

    std::cout << "[Receiver] Received public key + signature + size (" << received_bytes << " bytes)\n";
    std::cout << "\n";

    // Verify the signature using pre-shared sender's public key (kSenderPublicKeyPem)
    Botan::DataSource_Memory sender_key_source(kSenderPublicKeyPem);
    std::unique_ptr<Botan::Public_Key> sender_public_key = Botan::X509::load_key(sender_key_source);
    Botan::PK_Verifier verifier(*sender_public_key, "PSS(SHA-256)");
    
    // Separate the DER data and signature. Last 2 bytes (MSB) contains the signature size
    const size_t signature_size = static_cast<size_t>(pub_key_buffer[received_bytes - 2]) << 8 |
                                   static_cast<size_t>(pub_key_buffer[received_bytes - 1]);

    if (static_cast<size_t>(received_bytes) < signature_size) {
        std::cerr << "[Receiver] Received data is smaller than signature size\n";
        return kNOT_OK;
    }

    const size_t der_size = received_bytes - signature_size - 2;
    std::vector<uint8_t> der_data;
    std::vector<uint8_t> signature_data;
    der_data.assign(pub_key_buffer.begin(), pub_key_buffer.begin() + der_size);
    signature_data.assign(pub_key_buffer.begin() + der_size,
                         pub_key_buffer.begin() + der_size + signature_size);

    // Print received public key in hex
    std::cout << "[Receiver] Received (to be proved) public key (" << der_size << " bytes)\n";
    print_vector_hex_n(der_data, 10);
    std::cout << "\n";

    // Print received signature in hex
    std::cout << "[Receiver] Received signature (" << signature_size << " bytes)\n";
    print_vector_hex_n(signature_data, 10);
    std::cout << "\n";

    std::cout << "[Receiver] Verifying public key signature...\n";
    if (!verifier.verify_message(der_data, signature_data)) {
        std::cerr << "[Receiver] RESULT: Signature verification failed!\n";
        return kNOT_OK;
    }
    std::cout << "[Receiver] RESULT: Signature verification succeeded\n";
    std::cout << "[Receiver] (Proves authenticity and integrity of key)\n";
    std::cout << "\n";
    
    // Load the public key from DER data
    Botan::DataSource_Memory ds(
        reinterpret_cast<const uint8_t*>(der_data.data()),
        der_size
    );

    public_key = Botan::X509::load_key(ds);

    // Ensure it is RSA
    auto* rsa = dynamic_cast<Botan::RSA_PublicKey*>(public_key.get());
    if (!rsa) {
        std::cerr << "[Receiver] Received key is not an RSA public key\n";
        return kNOT_OK;
    }

    std::string pem = Botan::X509::PEM_encode(*public_key);
    std::cout << "[Receiver] The received RSA Public Key in PEM format\n";
    std::cout << "\n";
    std::cout << pem << std::endl;

    return kOK;
}

int send_symmetric_key(mqd_t mq, std::unique_ptr<Botan::Public_Key>& public_key, 
  std::vector<uint8_t>& symmetric_key) {
    Botan::AutoSeeded_RNG rng;

    // Generate a random symmetric key (e.g., 16 bytes for AES-128)
    rng.randomize(symmetric_key.data(), symmetric_key.size());
    std::cout << "[Receiver] Derived symmetric key\n";
    print_vector_hex_n(symmetric_key, 10);
    std::cout << "\n";

    // Encrypt the symmetric key using the received RSA public key (from Sender)
    Botan::RSA_PublicKey* rsa = dynamic_cast<Botan::RSA_PublicKey*>(public_key.get());
    Botan::PK_Encryptor_EME encryptor(*rsa, rng, "EME1(SHA-256)");
    std::vector<uint8_t> encrypted_key = encryptor.encrypt(symmetric_key, rng);
    std::cout << "[Receiver] Encrypted symmetric key with RSA public key (" << encrypted_key.size() << " bytes)\n";
    print_vector_hex_n(encrypted_key, 10);
    std::cout << "\n";

    // Add signature of the encrypted symmetric key using Receiver's private key
    Botan::DataSource_Memory receiver_key_source(kReceiverPrivateKeyPem);
    std::unique_ptr<Botan::Private_Key> receiver_private_key = Botan::PKCS8::load_key(receiver_key_source);
    Botan::PK_Signer signer(*receiver_private_key, rng, "PSS(SHA-256)");
    std::vector<uint8_t> signature = signer.sign_message(encrypted_key, rng);
    std::cout << "[Receiver] Signature of the encrypted symmetric key (" << signature.size() << " bytes)\n";
    print_vector_hex_n(signature, 10);
    std::cout << "\n";

    // Append signature to the encrypted key
    encrypted_key.insert(encrypted_key.end(), signature.begin(), signature.end());

    // Add length of signature to last two elements MSB
    const size_t signature_size = signature.size();
    encrypted_key.push_back(static_cast<uint8_t>(signature_size >> 8));
    encrypted_key.push_back(static_cast<uint8_t>(signature_size & 0xFF));

    // Send the encrypted symmetric key via message queue
    const int send_result = mq_send(
        mq,
        reinterpret_cast<const char*>(encrypted_key.data()),
        encrypted_key.size(),
        0
    );

    if (send_result == -1) {
        perror("mq_send");
        return kNOT_OK;
    }

    std::cout << "[Receiver] Sent encrypted symmetric key + signature + signature size (" << encrypted_key.size() << " bytes)\n";
    std::cout << "\n";
    return kOK;
}

int receive_periodic_messages(mqd_t mq, std::vector<uint8_t>& symmetric_key) {

    std::vector<uint8_t> buffer(kMessageSize);

    auto calculated_cmac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
    calculated_cmac->set_key(symmetric_key);

    while (true) {
        const ssize_t received_bytes =
            mq_receive(mq, reinterpret_cast<char*>(buffer.data()), buffer.size(),
                       nullptr);

        if (received_bytes > 0) {
          // Copy to exact size temporary vector
          std::vector<uint8_t> temp_vec(buffer.begin(), buffer.begin() + received_bytes);
          std::cout << "[Receiver] Received " << received_bytes << " bytes \n";
          print_vector_hex(temp_vec);


          // Extract received CMAC
          std::vector<uint8_t> received_cmac(temp_vec.end() - kCmacSize, temp_vec.end());
          std::cout << "[Receiver] Received CMAC\n";
          print_vector_hex(received_cmac);

          // Calculate CMAC of the encrypted key
          calculated_cmac->update(temp_vec.data(), received_bytes-kCmacSize);
          Botan::secure_vector<uint8_t> tag = calculated_cmac->final();
          std::cout << "[Receiver] Calculated CMAC of the received message\n";
          print_botan_secure_hex(tag);

          // Convert Botan::secure_vector to std::vector for comparison
          std::vector<uint8_t> calculated_cmac_vec;
          calculated_cmac_vec.reserve(tag.size());
          for (const auto& byte : tag) {
              calculated_cmac_vec.push_back(byte);
          }

         // Verify CMAC
         if (received_cmac != calculated_cmac_vec) {
             std::cerr << "[Receiver] CMAC verification failed!\n";
         }
         else {
            std::cout << "[Receiver] CMAC verification succeeded\n";
         }

        } else {
          perror("mq_receive");
          break;
        }
    }
    return kOK;
}

int setup_sender_communication(mqd_t& mq) {

  mq_attr queue_attr{};
  queue_attr.mq_flags = 0;
  queue_attr.mq_maxmsg = kMaxMessages;
  queue_attr.mq_msgsize = kMessageSize;

  mq =
    mq_open(kSenderToReceiverQueue.data(), O_CREAT | O_RDWR, kQueuePermissions, &queue_attr);
    if (mq == static_cast<mqd_t>(-1)) {
      perror("mq_open - queue for sending could not open");
      return kNOT_OK;
    }
    return kOK;
}

int setup_receiver_communication(mqd_t& mq) {

  mq_attr queue_attr{};
  queue_attr.mq_flags = 0;
  queue_attr.mq_maxmsg = kMaxMessages;
  queue_attr.mq_msgsize = kMessageSize;

  mq =
    mq_open(kReceiverToSenderQueue.data(), O_CREAT | O_RDWR, kQueuePermissions, &queue_attr);
    if (mq == static_cast<mqd_t>(-1)) {
      perror("mq_open - queue for receiving could not open");
      return kNOT_OK;
    }
    return kOK;
}

int main() {

  // Open for reading from sender queue
  mqd_t mq_receiver_to_sender;
  if (setup_receiver_communication(mq_receiver_to_sender) != kOK) {
      return kNOT_OK;
  }

  // Set up queue for sending
  mqd_t mq_sender_to_receiver;
  if (setup_sender_communication(mq_sender_to_receiver) != kOK) {
      return kNOT_OK;
  }

  std::cout << "[Receiver] Starting receiver in 5 seconds...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(4000));
  std::cout << "[Receiver] Running...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  std::cout << "\n";

  unsigned int message_id{kMessageIdRsaPublicKey};
  unsigned int status{kNOT_OK};
  std::unique_ptr<Botan::Public_Key> public_key;
  std::vector<uint8_t> symmetric_key(kSymKeySize);
  switch(message_id) {
      case kMessageIdRsaPublicKey:
          std::cout << "[Receiver] Wait for public key...\n";
          status = get_public_key(mq_sender_to_receiver, public_key);
          message_id = kMessageIdSymKey;
          [[fallthrough]];
      case kMessageIdSymKey:
          std::cout << "[Receiver] Send symmetric key\n";
          status = send_symmetric_key(mq_receiver_to_sender, public_key, symmetric_key);
          message_id = kMessageIdPeriodic;
          [[fallthrough]];
      case kMessageIdPeriodic:
          std::cout << "[Receiver] Receive periodic messages\n";
          status = receive_periodic_messages(mq_sender_to_receiver, symmetric_key);
          break;
      default:
          std::cout << "Unknown message ID.\n";
          break;
  }

  // Don't close terminal right away
  std::cout << "Receiver done. Press Enter to exit.";
  std::cin.get();

  mq_close(mq_receiver_to_sender);
  mq_close(mq_sender_to_receiver);
  return status;
}
