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
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
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
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+MZnAUHRoeB32
TFnPJ2O4VAR2oCFvY1e/HQ8Aq8Iyx77PB3ZInxUcy/ZPOKayj78ZCaQJJx3LTA8b
fwkdbmwVWcZ0VMpiLs4AFEPan0QTfd5tUldi82MFcXqi1NbqOppBufaYUcpZcNRK
MFzPnPZtnXcO1pVOnR7pUHaPnxQ9tXw4kgPVl3O9o5CLubwliumPtdn7UBvmiwHf
fzg9ZYaGPOnham8Z2KKv4qI/OJEQE9PFg899PgFJD+zR7vGa31CbbZoeYB1jW4dq
rCyRaXOxtPeA0AcKyrxRTLrOn5caHpwbx4jiNNfx5XaPsM/3ZF5L4DrWucyXCbDw
bABXrm1rAgMBAAECggEAU8dcj0rBZE1ZAWfzfZ0/v2//AVQbNko/2jcOJ0EBi8XS
BrcmQuoUbjloF9CAGZLZXkmRYNjCto0b8IQ+eyDramI/2XmKJsKwSneixhg28BEX
W/eT98n3Wev5VeXEf6vtzDsC5WjN5iUd1kpEb82X/YQJ8FbUsSrj9WlUuIId8+oN
1oXluEsi7NHjHRkdGD7SkN5PUWOxTGeERvCrKqjeKSp/1f2nEPltFq8Os17foJHJ
lDqU8m6RLtCw17vLsWXV0JujSA0eaWfGrVnCjQ31pzxAPkTAlNP4UVJ0vKVnvaeR
7yJ/cCebsuyf7vM3H0wxr6cN4LcKHfNOGxxBhA0HVQKBgQDdA9gcwGJYM35dIoLH
K8NqyawFW7i4EeHl6H+pQc7JKdOL8tUvzAxAWTTDq2YNtkdmcZ9dcSTyKRwr6QcU
L8JfVQih2Q99s+tBdp3bIMdyBVxgnRhwU3DYv4RSRkR3sTqg6zeoQYv1MppOsNrr
fdGKhS4YvRiLBF9c9E8A/kMZRwKBgQDcTMqSbLq9KPlBzbYek2a7Qlbj20Rhm8Q1
Jlbo6aGYcIpB77j9CcTmLxwaA7TnTf3odht6PI5Ldlxw4OtGdc6vzNOCBFrScuRb
Pmm4KWgWz/SeVXgGlA1qjEzUo5i4K5kXhT7jIH9ZqyXC8gUJmGrY0H4cKSY3igGy
kcoj3BccvQKBgQDU4YAG6ZOQa0D6ymP3HgMjV89WdetteOQChDh6ukVIY/48nZCU
clEWphX5pp0s9fa+CRE8et/gVJKrBNBptDrfglNHOYD/Tg56xprz1xXkkJ9S+93v
S5+1VntImCAYvd+/4fCBI2mAqtYQl662B0GO0Ar/jxwVwwdrzHJQfZf5vwKBgQDU
n1Ugj8qICYTRaw8sYY3UjIm6b4WHQ8TSm4dkUyHBNFVsoEeGCai9lZhkz1EJsi+u
7ldE2i9oS/uagqrxnYB4EpPNOBDEb1lRa2Kz+VraManiK5Gln713KaR50s/yaTng
Bp2Ur2fajqHqjpYoFbCCRHCDE4AsOIm85JMZmzG/bQKBgDkObXyEBPIdzNIy2clr
csVO5YRYAlpc1DgLAVaB+2j0vwD7cerU2Y5tNxtTSVGZbABUQmKmzIecWKsE2AKI
5JQgMeeHc5tuz3RbBfZcXokd+xFxtbwKOck6M+d6JtWLUdkYt4axzu21y6B8oZ8+
EPMxH8hoznzjgYsWN0s24LPo
-----END PRIVATE KEY-----)";

const std::string kSenderPublicKeyPem = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhkaHXuDKr8N2glMxtTRU
YqCdR6cjFgtbr2kipmrDscBtd/vKzRgfQWQlr55aAdeVGd0QPEdSBubXRqNjYeg1
vfHWMj0lq9ZRpPrhk5gO/F4TKxT/AFG3rP3wvS138sbctK4YoyRb+yeg5Mw3dsgi
NeP+L6KbDDchA+Cdx8MkofxWKzW74GdR8LlMZYPFFKVu2naMwR7S+u40KUwveOGt
bYkNBE/XrDjyV1Sbx0mBPLcAuXpes9KosvYY+wTXJaG4gb1qYa8dxmf1nnsod67Z
mwEOu8RIOjF9pY2P/hqee8DccNSYtAEap8FpeZZmDaMzarkQHw/dld9IzMjD0yMl
tQIDAQAB
-----END PUBLIC KEY-----)";


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

void print_vector_hex_n(const std::vector<uint8_t>& vec, size_t n = 64) {
    std::cout << "[Sender] 0x";
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

    // Add signature to the message using sender's private key (PEM format)
    Botan::DataSource_Memory key_source(kSenderPrivateKeyPem);
    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<Botan::Private_Key> private_key = Botan::PKCS8::load_key(key_source);
    Botan::PK_Signer signer(*private_key, rng, "PSS(SHA-256)");
    std::vector<uint8_t> signature = signer.sign_message(der, rng);

    // Print first and last 10 bytes of public key DER
    std::cout << "[Sender] Public key DER data (" << der.size() << " bytes)\n";
    print_vector_hex_n(der, 10);
    std::cout << "\n";

    // Print first and last 10 bytes of signature
    std::cout << "[Sender] Public key signature (" << signature.size() << " bytes)\n";
    print_vector_hex_n(signature, 10);
    std::cout << "\n";

    // Append signature to the DER data
    der.insert(der.end(), signature.begin(), signature.end());

    // Add length of signature to last two elements MSB (cannot get this from Botan during verification)
    const size_t signature_size = signature.size();
    der.push_back(static_cast<uint8_t>(signature_size >> 8));
    der.push_back(static_cast<uint8_t>(signature_size & 0xFF));

    // Ensure the message fits in the queue
    if (der.size() > kMessageSize) {
        std::cerr << "[Sender] Public key + signature + signature size too large for message queue\n";
        std::cin.get();
        return kNOT_OK;
    }

    // Send the public key + signature via message queue
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

    std::cout << "[Sender] Sent public key + signature + signature size (" << der.size() << " bytes)\n";

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
    print_vector_hex_n(encrypted_data, 10);
    std::cout << "\n";

    std::this_thread::sleep_for(std::chrono::milliseconds(40000));

    // TODO: Fix with signature verification

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
    std::cout << "\n";

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
          std::cout << "[Sender] Send public key (used to encrypt symmetric key generated by receiver)\n";
          status = send_public_key(mq_sender_to_receiver, public_key);
          message_id = kMessageIdSymKey;
          [[fallthrough]];
      case kMessageIdSymKey:
          std::cout << "[Sender] Wait for symmetric key...\n";
          std::cout << "\n";
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