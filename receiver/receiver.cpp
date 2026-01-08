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
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>

// Project headers
#include "common.hpp"

// Private key for signing (PEM format)
const std::string kReceiverPrivateKeyPem = R"(-----BEGIN PRIVATE KEY-----
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
mUscM89dY2PHH6oNj/pvHUc=
-----END PRIVATE KEY-----)";

// Pre-shared public key for verifying signatures (PEM format)
const std::string kSenderPublicKeyPem = R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxlKCLeQG/DVoj4+Mx+7n
acfQQxML1WKJzy2i5h1wWUFt7nIPBIKqjmB7Ex2YU+PYREI2jos7DgCIZQTApx8o
1yEsKop5eNqdvRKAMIic364pounquC8jTVrhMRIGZ72B8a02qYqm4uK07Fnvy6yu
2BV5S3KgmCVCSuJnIktnsZ1guLyEE+fOFMexkYNHXDusHiwMq7Cnb02qION9KMID
77AwU2RIi344L2yU5jH3iJM3XMblamtBqVujewthNoMhsno/MraaBmPHleI02AuU
DCita8BhTaie3qlOINZAcidzSByXqtpk/YIL2siWyKstaQwwo3UHHTgC893dW5U3
qwIka6GFsq30Mhdpk2+YwBFsc0vvXY64XTSn8DNuwXJmuMko+7nmEKSx+/CBaQY1
nmUCLcC2vdcAuUyKPxJ+y3lk4F6O3gJoeyymWpDV6l90XNXSK+VitUrI+iFBqG8K
1j0wyEKl/4Ly8Ry4axodP6askaA0o8KIGlxbMYv2IkEdAgMBAAE=
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
    //std::array<std::byte, kMessageSize> pub_key_buffer{};
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

    std::cout << "[Receiver] Received public key (" << received_bytes << " bytes)\n";
    std::cout << "[Receiver] The received public key raw data \n";
    print_vector_hex(pub_key_buffer);
    std::cout << "\n";

    std::this_thread::sleep_for(std::chrono::milliseconds(4000));

    // Verify the signature using pre-shared sender's public key (kSenderPublicKeyPem)
    Botan::DataSource_Memory sender_key_source(kSenderPublicKeyPem);
    std::unique_ptr<Botan::Public_Key> sender_public_key = Botan::X509::load_key(sender_key_source);
    Botan::PK_Verifier verifier(*sender_public_key, "PSS(SHA-256)");
    
    // Separate the DER data and signature. Last byte contains the signature size
    const size_t signature_size = static_cast<size_t>(pub_key_buffer[received_bytes - 1]);

    if (static_cast<size_t>(received_bytes) < signature_size) {
        std::cerr << "[Receiver] Received data is smaller than signature size\n";
        return kNOT_OK;
    }

    const size_t der_size = received_bytes - signature_size - 1;
    std::vector<uint8_t> der_data(der_size);
    std::vector<uint8_t> signature_data(signature_size);
    std::memcpy(der_data.data(), pub_key_buffer.data(), der_size);
    std::memcpy(signature_data.data(), pub_key_buffer.data() + der_size, signature_size);
    if (!verifier.verify_message(der_data.data(), der_size, signature_data.data(), signature_size)) {
        std::cerr << "[Receiver] Public key signature verification failed!\n";
        return kNOT_OK;
    }
    std::cout << "[Receiver] Public key signature verification succeeded\n";
    
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
    std::cout << "[Receiver] Received RSA Public Key in PEM format\n";
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
    print_vector_hex(symmetric_key);
    std::cout << "\n";

    // Encrypt the symmetric key using the received RSA public key
    Botan::RSA_PublicKey* rsa = dynamic_cast<Botan::RSA_PublicKey*>(public_key.get());
    Botan::PK_Encryptor_EME encryptor(*rsa, rng, "EME1(SHA-256)");
    std::vector<uint8_t> encrypted_key = encryptor.encrypt(symmetric_key, rng);
    std::cout << "[Receiver] Encrypted symmetric key with RSA public key\n";
    print_vector_hex(encrypted_key);
    std::cout << "\n";

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

    std::cout << "[Receiver] Sent encrypted symmetric key (" << encrypted_key.size() << " bytes)\n";
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
         std::cout << "[Receiver] CMAC verification succeeded\n";

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
