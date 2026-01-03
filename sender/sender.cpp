// C system headers
#include <cstring>
#include <mqueue.h>

// C++ standard library headers
#include <array>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <span>
#include <string_view>
#include <thread>
#include <vector>

// Third-party (Botan) headers (alphabetical)
#include <botan/auto_rng.h>
#include <botan/mac.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>

// Project headers
#include "common.hpp"

// Pre-shared public key for verifying signatures (PEM format) from receiver
const std::string kReceiverPublicKeyPem = R"(-----BEGIN PUBLIC KEY-----
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

// Private key for signing messages (PEM format)
const std::string kSenderPrivateKeyPem = R"(-----BEGIN PRIVATE KEY-----
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
9E+0Lpd3ro5QhtREpUhGPLY9
-----END PRIVATE KEY-----)";

// Automatically unlinks the message queue when destroyed.
class MqUnlinker {
 public:
  explicit MqUnlinker(std::string_view name) : name_(name) {}
  ~MqUnlinker() { mq_unlink(name_.data()); }

  MqUnlinker(const MqUnlinker&) = delete;
  MqUnlinker& operator=(const MqUnlinker&) = delete;

 private:
  std::string_view name_;
};

Botan::secure_vector<uint8_t> calculate_mac(std::span<const std::byte> data, std::vector<uint8_t>& symmetric_key) {
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
    mac->set_key(symmetric_key);
    mac->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return mac->final();
}

void print_buffer_hex(const std::array<std::byte, kBufferSize>& buffer) {
    std::cout << "[Sender] 0x";
    for (auto b : buffer) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(b);
    }
    std::cout << std::dec;  // reset to decimal
}

void print_vector_hex(const std::vector<uint8_t>& vec) {
    std::cout << "[Sender] 0x";
    for (const auto& byte : vec) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(byte);
    }
    std::cout << std::dec;  // reset to decimal
    std::cout << "\n";
}

void print_botan_secure_hex(const Botan::secure_vector<uint8_t>& vec) {
    std::cout << "[Sender] 0x";
    for (const auto& byte : vec) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(byte);
    }
    std::cout << std::dec;  // reset to decimal
    std::cout << "\n";
}

int send_public_key(mqd_t mq, const Botan::RSA_PublicKey& public_key)
{
    // Get X.509 SubjectPublicKeyInfo DER
    std::vector<uint8_t> der = public_key.subject_public_key();

    if (der.size() > kMessageSize) {
        std::cerr << "[Sender] Public key too large for message queue\n";
        return kNOT_OK;
    }

    if (mq_send(mq,
                reinterpret_cast<const char*>(der.data()),
                der.size(),
                0) == -1)
    {
        perror("mq_send");
        std::cout << "[Sender] Public key send failed. Press Enter to exit.";
        std::cin.get();
        return kNOT_OK;
    }

    std::cout << "[Sender] Public key sent (" << der.size() << " bytes)\n";
    return kOK;
}


int send_periodic_message(mqd_t mq, std::vector<uint8_t>& symmetric_key) {
    // Implementation for sending periodic messages
 
    std::vector<uint8_t> buffer(kBufferSize + kCmacSize, 0xFF);
    unsigned int status{kOK};
    
    // Setup MAC
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
    mac->set_key(symmetric_key);

    for (int message_index = 0; message_index < kNumMessagesToSend; ++message_index) {
      // Add a byte counter at the end of the message
      buffer[19] = static_cast<uint8_t>(message_index % 256);

      // Calculate CMAC of the buffer (first kBufferSize bytes)
      mac->update(reinterpret_cast<const uint8_t*>(buffer.data()), kBufferSize);
      Botan::secure_vector<uint8_t> tag = mac->final();

      // Convert Botan::secure_vector to std::vector for appending
      std::vector<uint8_t> mac_vec;
      mac_vec.reserve(tag.size());
      for (const auto& byte : tag) {
        mac_vec.push_back(byte);
      }

      // Insert CMAC at the end of the buffer
      std::memcpy(buffer.data() + kBufferSize, mac_vec.data(), kCmacSize);

      const int send_result =
          mq_send(mq, reinterpret_cast<const char*>(buffer.data()), buffer.size(), 0);

      if (send_result == -1) {
        perror("mq_send");
        status = kNOT_OK;
        break;
      }

      std::cout << "[Sender] Sent " << buffer.size() << " bytes Message + CMAC (msg #"
                << message_index << ")\n";
      print_vector_hex(buffer);

      std::this_thread::sleep_for(kSendPeriod);
    }

    return status;
}

// Receive, decrypt and return symmetric key
int receive_symmetric_key(mqd_t mq, const Botan::RSA_PrivateKey& private_key,
    std::vector<uint8_t>& symmetric_key) {

    std::vector<uint8_t> buffer(kMessageSize);

    unsigned int msg_prio;

    const ssize_t bytes_received = mq_receive(
        mq, reinterpret_cast<char*>(buffer.data()), buffer.size(), &msg_prio);

    if (bytes_received == -1) {
      perror("mq_receive");
      std::cout << "[Sender]Symmetric key receive failed. Press Enter to exit.";
      std::cin.get();
      return kNOT_OK;
    }

    std::vector<uint8_t> encrypted_data(bytes_received);
    std::memcpy(encrypted_data.data(), buffer.data(), bytes_received);

    std::cout << "[Sender] Received encrypted symmetric key (" << bytes_received << " bytes)\n";
    print_vector_hex(encrypted_data);

    // Copy the encrypted data with 16 bytes less for CMAC
    std::vector<uint8_t> encrypted_key(
        encrypted_data.begin(), encrypted_data.end());

    // Decrypt the symmetric key using RSA private key (Bootan::secure_vector)
    Botan::AutoSeeded_RNG rng;
    Botan::PK_Decryptor_EME decryptor(private_key, rng, "EME1(SHA-256)");
    Botan::secure_vector<uint8_t> symmetric_key_secure;
    symmetric_key_secure = decryptor.decrypt(std::span<const uint8_t>(encrypted_key));

    std::cout << "[Sender] Decrypted symmetric key (" << symmetric_key_secure.size() << " bytes)\n";
    print_botan_secure_hex(symmetric_key_secure);

    // Botan::secure_vector to std::vector
    symmetric_key.assign(symmetric_key_secure.begin(), symmetric_key_secure.end());

    std::fill(buffer.begin(), buffer.end(), 0);  // Clear sensitive data

    std::cout << "[Sender] Received symmetric key (" << symmetric_key.size() << " bytes)\n";
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

  // Setup queue for sending
  mqd_t mq_sender_to_receiver;
  if (setup_sender_communication(mq_sender_to_receiver) != kOK) {
    return kNOT_OK;
  }

  // Open queue for reading
  mqd_t mq_receiver_to_sender;
  if (setup_receiver_communication(mq_receiver_to_sender) != kOK) {
    return kNOT_OK;
  }

  std::cout << "[Sender] Starting sender in 5 seconds...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(4000));
  std::cout << "[Sender] Running...\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  std::cout << "\n";
   
  
  // Generate RSA private key (e.g., 2048 bits)
  Botan::AutoSeeded_RNG rng;
  Botan::RSA_PrivateKey private_key(rng, 2048);

  // Extract public key
  Botan::RSA_PublicKey public_key(private_key);

  std::string public_pem = Botan::X509::PEM_encode(public_key);
  std::string private_pem = Botan::PKCS8::PEM_encode(private_key);

  std::cout << private_pem << "\n";
  std::cout << public_pem  << "\n";

  std::vector<uint8_t> symmetric_key(kSymKeySize);
  rng.randomize(symmetric_key.data(), symmetric_key.size());
  unsigned int message_id{kMessageIdRsaPublicKey};
  unsigned int status{kNOT_OK};
  switch(message_id) {
      case kMessageIdRsaPublicKey:
          std::cout << "[Sender] Send public key\n";
          status = send_public_key(mq_sender_to_receiver, public_key);
          message_id = kMessageIdSymKey;
          [[fallthrough]];
      case kMessageIdSymKey:
          std::cout << "[Sender] Wait for symmetric key...\n";
          receive_symmetric_key(mq_receiver_to_sender, private_key, symmetric_key);
          message_id = kMessageIdPeriodic;
          [[fallthrough]];
      case kMessageIdPeriodic:
          std::cout << "[Sender] Send periodic messages\n";
          status = send_periodic_message(mq_sender_to_receiver, symmetric_key);
          break;
      default:
          std::cout << "Unknown message ID.\n";
          break;
  }

  MqUnlinker unlinkSenderQueue(kSenderToReceiverQueue);
  MqUnlinker unlinkReceiverQueue(kReceiverToSenderQueue);

  mq_close(mq_sender_to_receiver);
  mq_close(mq_receiver_to_sender);

  // Don't close terminal right away
  std::cout << "Sender done. Press Enter to exit.";
  std::cin.get();
  return status;
}