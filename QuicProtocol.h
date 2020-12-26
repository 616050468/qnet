#ifndef QNET_PROTOCOL_H_
#define QNET_PROTOCOL_H_

#include <stddef.h>
#include <stdint.h>
#include <array>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace qnet {
typedef uint64_t QuicByteCount;
typedef uint64_t QuicPacketCount;

typedef uint64_t QuicConnectionId;
typedef uint32_t QuicStreamId;
typedef uint64_t QuicStreamOffset;
typedef uint64_t QuicPacketNumber;
typedef uint8_t QuicPathId;
typedef uint64_t QuicPublicResetNonceProof;
typedef uint8_t QuicPacketEntropyHash;
typedef uint32_t QuicHeaderId;
typedef uint16_t QuicPacketLength;

// Default initial maximum size in bytes of a QUIC packet.
const QuicByteCount kDefaultMaxPacketSize = 1350;
// Default initial maximum size in bytes of a QUIC packet for servers.
const QuicByteCount kDefaultServerMaxPacketSize = 1000;
// Minimum size of a QUIC packet, used if a server receives packets from a
// client with unusual network headers. 1280 - sizeof(eth) - sizeof(ipv6).
const QuicByteCount kMinimumSupportedPacketSize = 1214;
// The maximum packet size of any QUIC packet, based on ethernet's max size,
// minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
// max packet size is 1500 bytes,  1500 - 48 = 1452.
const QuicByteCount kMaxPacketSize = 1452;
// Default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
const QuicByteCount kDefaultTCPMSS = 1460;

// We match SPDY's use of 32 (since we'd compete with SPDY).
const QuicPacketCount kInitialCongestionWindow = 32;

// Minimum size of initial flow control window, for both stream and session.
const uint32_t kMinimumFlowControlSendWindow = 16 * 1024;  // 16 KB

// Maximum flow control receive window limits for connection and stream.
const QuicByteCount kStreamReceiveWindowLimit = 16 * 1024 * 1024;   // 16 MB
const QuicByteCount kSessionReceiveWindowLimit = 24 * 1024 * 1024;  // 24 MB

// Minimum size of the CWND, in packets, when doing bandwidth resumption.
const QuicPacketCount kMinCongestionWindowForBandwidthResumption = 10;

// Maximum number of tracked packets.
const QuicPacketCount kMaxTrackedPackets = 10000;

// Default size of the socket receive buffer in bytes.
const QuicByteCount kDefaultSocketReceiveBuffer = 1024 * 1024;
// Minimum size of the socket receive buffer in bytes.
// Smaller values are ignored.
const QuicByteCount kMinSocketReceiveBuffer = 16 * 1024;

// Fraction of the receive buffer that can be used, based on conservative
// estimates and testing on Linux.
// An alternative to kUsableRecieveBufferFraction.
static const float kConservativeReceiveBufferFraction = 0.6f;

// Don't allow a client to suggest an RTT shorter than 10ms.
const uint32_t kMinInitialRoundTripTimeUs = 10 * kNumMicrosPerMilli;

// Don't allow a client to suggest an RTT longer than 15 seconds.
const uint32_t kMaxInitialRoundTripTimeUs = 15 * kNumMicrosPerSecond;

// Maximum number of open streams per connection.
const size_t kDefaultMaxStreamsPerConnection = 100;

// Number of bytes reserved for public flags in the packet header.
const size_t kPublicFlagsSize = 1;
// Number of bytes reserved for version number in the packet header.
const size_t kQuicVersionSize = 4;
// Number of bytes reserved for path id in the packet header.
const size_t kQuicPathIdSize = 1;
// Number of bytes reserved for private flags in the packet header.
const size_t kPrivateFlagsSize = 1;

// Signifies that the QuicPacket will contain version of the protocol.
const bool kIncludeVersion = true;
// Signifies that the QuicPacket will contain path id.
const bool kIncludePathId = true;
// Signifies that the QuicPacket will include a diversification nonce.
const bool kIncludeDiversificationNonce = true;

// Stream ID is reserved to denote an invalid ID.
const QuicStreamId kInvalidStreamId = 0;

// Reserved ID for the crypto stream.
const QuicStreamId kCryptoStreamId = 1;

// Reserved ID for the headers stream.
const QuicStreamId kHeadersStreamId = 3;

// The largest gap in packets we'll accept without closing the connection.
// This will likely have to be tuned.
const QuicPacketNumber kMaxPacketGap = 5000;

enum TransmissionType : int8_t {
  NOT_RETRANSMISSION,
  FIRST_TRANSMISSION_TYPE = NOT_RETRANSMISSION,
  HANDSHAKE_RETRANSMISSION,    // Retransmits due to handshake timeouts.
  ALL_UNACKED_RETRANSMISSION,  // Retransmits all unacked packets.
  ALL_INITIAL_RETRANSMISSION,  // Retransmits all initially encrypted packets.
  LOSS_RETRANSMISSION,         // Retransmits due to loss detection.
  RTO_RETRANSMISSION,          // Retransmits due to retransmit time out.
  TLP_RETRANSMISSION,          // Tail loss probes.
  LAST_TRANSMISSION_TYPE = TLP_RETRANSMISSION,
};

enum HasRetransmittableData : int8_t {
  NO_RETRANSMITTABLE_DATA,
  HAS_RETRANSMITTABLE_DATA,
};

enum IsHandshake : int8_t { NOT_HANDSHAKE, IS_HANDSHAKE };

enum class Perspective { IS_SERVER, IS_CLIENT };

// Describes whether a ConnectionClose was originated by the peer.
enum class ConnectionCloseSource { FROM_PEER, FROM_SELF };

// Should a connection be closed silently or not.
enum class ConnectionCloseBehavior {
  SILENT_CLOSE,
  SEND_CONNECTION_CLOSE_PACKET,
  SEND_CONNECTION_CLOSE_PACKET_WITH_NO_ACK
};

enum QuicFrameType {
  // Regular frame types. The values set here cannot change without the
  // introduction of a new QUIC version.
  PADDING_FRAME = 0,
  RST_STREAM_FRAME = 1,
  CONNECTION_CLOSE_FRAME = 2,
  GOAWAY_FRAME = 3,
  WINDOW_UPDATE_FRAME = 4,
  BLOCKED_FRAME = 5,
  STOP_WAITING_FRAME = 6,
  PING_FRAME = 7,
  PATH_CLOSE_FRAME = 8,

  // STREAM and ACK frames are special frames. They are encoded differently on
  // the wire and their values do not need to be stable.
  STREAM_FRAME,
  ACK_FRAME,
  // The path MTU discovery frame is encoded as a PING frame on the wire.
  MTU_DISCOVERY_FRAME,
  NUM_FRAME_TYPES
};

enum QuicConnectionIdLength {
  PACKET_0BYTE_CONNECTION_ID = 0,
  PACKET_8BYTE_CONNECTION_ID = 8
};

enum QuicPacketNumberLength : int8_t {
  PACKET_1BYTE_PACKET_NUMBER = 1,
  PACKET_2BYTE_PACKET_NUMBER = 2,
  PACKET_4BYTE_PACKET_NUMBER = 4,
  PACKET_6BYTE_PACKET_NUMBER = 6
};

// Used to indicate a QuicSequenceNumberLength using two flag bits.
enum QuicPacketNumberLengthFlags {
  PACKET_FLAGS_1BYTE_PACKET = 0,           // 00
  PACKET_FLAGS_2BYTE_PACKET = 1,           // 01
  PACKET_FLAGS_4BYTE_PACKET = 1 << 1,      // 10
  PACKET_FLAGS_6BYTE_PACKET = 1 << 1 | 1,  // 11
};

// The public flags are specified in one byte.
enum QuicPacketPublicFlags {
  PACKET_PUBLIC_FLAGS_NONE = 0,

  // Bit 0: Does the packet header contains version info?
  PACKET_PUBLIC_FLAGS_VERSION = 1 << 0,

  // Bit 1: Is this packet a public reset packet?
  PACKET_PUBLIC_FLAGS_RST = 1 << 1,

  // Bit 2: indicates the that public header includes a nonce.
  PACKET_PUBLIC_FLAGS_NONCE = 1 << 2,

  // Bit 3: indicates whether a ConnectionID is included.
  PACKET_PUBLIC_FLAGS_0BYTE_CONNECTION_ID = 0,
  PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID = 1 << 3,

  // QUIC_VERSION_32 and earlier use two bits for an 8 byte
  // connection id.
  PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID_OLD = 1 << 3 | 1 << 2,

  // Bits 4 and 5 describe the packet number length as follows:
  // --00----: 1 byte
  // --01----: 2 bytes
  // --10----: 4 bytes
  // --11----: 6 bytes
  PACKET_PUBLIC_FLAGS_1BYTE_PACKET = PACKET_FLAGS_1BYTE_PACKET << 4,
  PACKET_PUBLIC_FLAGS_2BYTE_PACKET = PACKET_FLAGS_2BYTE_PACKET << 4,
  PACKET_PUBLIC_FLAGS_4BYTE_PACKET = PACKET_FLAGS_4BYTE_PACKET << 4,
  PACKET_PUBLIC_FLAGS_6BYTE_PACKET = PACKET_FLAGS_6BYTE_PACKET << 4,

  // Bit 6: Does the packet header contain a path id?
  PACKET_PUBLIC_FLAGS_MULTIPATH = 1 << 6,

  // Reserved, unimplemented flags:

  // Bit 7: indicates the presence of a second flags byte.
  PACKET_PUBLIC_FLAGS_TWO_OR_MORE_BYTES = 1 << 7,

  // All bits set (bit 7 is not currently used): 01111111
  PACKET_PUBLIC_FLAGS_MAX = (1 << 7) - 1,
};

// The private flags are specified in one byte.
enum QuicPacketPrivateFlags {
  PACKET_PRIVATE_FLAGS_NONE = 0,

  // Bit 0: Does this packet contain an entropy bit?
  PACKET_PRIVATE_FLAGS_ENTROPY = 1 << 0,

  // Bit 1: Payload is part of an FEC group?
  PACKET_PRIVATE_FLAGS_FEC_GROUP = 1 << 1,

  // Bit 2: Payload is FEC as opposed to frames?
  PACKET_PRIVATE_FLAGS_FEC = 1 << 2,

  // All bits set (bits 3-7 are not currently used): 00000111
  PACKET_PRIVATE_FLAGS_MAX = (1 << 3) - 1,

  // For version 32 (bits 1-7 are not used): 00000001
  PACKET_PRIVATE_FLAGS_MAX_VERSION_32 = (1 << 1) - 1
};

// The available versions of QUIC. Guaranteed that the integer value of the enum
// will match the version number.
// When adding a new version to this enum you should add it to
// kSupportedQuicVersions (if appropriate), and also add a new case to the
// helper methods QuicVersionToQuicTag, QuicTagToQuicVersion, and
// QuicVersionToString.
enum QuicVersion {
  // Special case to indicate unknown/unsupported QUIC version.
  QUIC_VERSION_UNSUPPORTED = 0,

  QUIC_VERSION_30 = 30,  // Add server side support of cert transparency.
  QUIC_VERSION_31 = 31,  // Adds a hash of the client hello to crypto proof.
  QUIC_VERSION_32 = 32,  // FEC related fields are removed from wire format.
  QUIC_VERSION_33 = 33,  // Adds diversification nonces.
  QUIC_VERSION_34 = 34,  // Deprecates entropy, removes private flag from packet
                         // header, uses new ack and stop waiting wire format.
  QUIC_VERSION_35 = 35,  // Allows endpoints to independently set stream limit.
  QUIC_VERSION_36 = 36,  // Add support to force HOL blocking.

  // IMPORTANT: if you are adding to this std::list, follow the instructions at
  // http://sites/quic/adding-and-removing-versions
};

// This vector contains QUIC versions which we currently support.
// This should be ordered such that the highest supported version is the first
// element, with subsequent elements in descending order (versions can be
// skipped as necessary).
//
// IMPORTANT: if you are adding to this list, follow the instructions at
// http://sites/quic/adding-and-removing-versions
static const QuicVersion kSupportedQuicVersions[] = {
    QUIC_VERSION_36, QUIC_VERSION_35, QUIC_VERSION_34, QUIC_VERSION_33,
    QUIC_VERSION_32, QUIC_VERSION_31, QUIC_VERSION_30};

typedef std::vector<QuicVersion> QuicVersionVector;

// These values must remain stable as they are uploaded to UMA histograms.
// To add a new error code, use the current value of QUIC_LAST_ERROR and
// increment QUIC_LAST_ERROR.
enum QuicErrorCode {
  QUIC_NO_ERROR = 0,

  // Connection has reached an invalid state.
  QUIC_INTERNAL_ERROR = 1,
  // There were data frames after the a fin or reset.
  QUIC_STREAM_DATA_AFTER_TERMINATION = 2,
  // Control frame is malformed.
  QUIC_INVALID_PACKET_HEADER = 3,
  // Frame data is malformed.
  QUIC_INVALID_FRAME_DATA = 4,
  // The packet contained no payload.
  QUIC_MISSING_PAYLOAD = 48,
  // FEC data is malformed.
  QUIC_INVALID_FEC_DATA = 5,
  // STREAM frame data is malformed.
  QUIC_INVALID_STREAM_DATA = 46,
  // STREAM frame data overlaps with buffered data.
  QUIC_OVERLAPPING_STREAM_DATA = 87,
  // Received STREAM frame data is not encrypted.
  QUIC_UNENCRYPTED_STREAM_DATA = 61,
  // Attempt to send unencrypted STREAM frame.
  QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA = 88,
  // Received a frame which is likely the result of memory corruption.
  QUIC_MAYBE_CORRUPTED_MEMORY = 89,
  // FEC frame data is not encrypted.
  QUIC_UNENCRYPTED_FEC_DATA = 77,
  // RST_STREAM frame data is malformed.
  QUIC_INVALID_RST_STREAM_DATA = 6,
  // CONNECTION_CLOSE frame data is malformed.
  QUIC_INVALID_CONNECTION_CLOSE_DATA = 7,
  // GOAWAY frame data is malformed.
  QUIC_INVALID_GOAWAY_DATA = 8,
  // WINDOW_UPDATE frame data is malformed.
  QUIC_INVALID_WINDOW_UPDATE_DATA = 57,
  // BLOCKED frame data is malformed.
  QUIC_INVALID_BLOCKED_DATA = 58,
  // STOP_WAITING frame data is malformed.
  QUIC_INVALID_STOP_WAITING_DATA = 60,
  // PATH_CLOSE frame data is malformed.
  QUIC_INVALID_PATH_CLOSE_DATA = 78,
  // ACK frame data is malformed.
  QUIC_INVALID_ACK_DATA = 9,

  // Version negotiation packet is malformed.
  QUIC_INVALID_VERSION_NEGOTIATION_PACKET = 10,
  // Public RST packet is malformed.
  QUIC_INVALID_PUBLIC_RST_PACKET = 11,
  // There was an error decrypting.
  QUIC_DECRYPTION_FAILURE = 12,
  // There was an error encrypting.
  QUIC_ENCRYPTION_FAILURE = 13,
  // The packet exceeded kMaxPacketSize.
  QUIC_PACKET_TOO_LARGE = 14,
  // The peer is going away.  May be a client or server.
  QUIC_PEER_GOING_AWAY = 16,
  // A stream ID was invalid.
  QUIC_INVALID_STREAM_ID = 17,
  // A priority was invalid.
  QUIC_INVALID_PRIORITY = 49,
  // Too many streams already open.
  QUIC_TOO_MANY_OPEN_STREAMS = 18,
  // The peer created too many available streams.
  QUIC_TOO_MANY_AVAILABLE_STREAMS = 76,
  // Received public reset for this connection.
  QUIC_PUBLIC_RESET = 19,
  // Invalid protocol version.
  QUIC_INVALID_VERSION = 20,

  // The Header ID for a stream was too far from the previous.
  QUIC_INVALID_HEADER_ID = 22,
  // Negotiable parameter received during handshake had invalid value.
  QUIC_INVALID_NEGOTIATED_VALUE = 23,
  // There was an error decompressing data.
  QUIC_DECOMPRESSION_FAILURE = 24,
  // The connection timed out due to no network activity.
  QUIC_NETWORK_IDLE_TIMEOUT = 25,
  // The connection timed out waiting for the handshake to complete.
  QUIC_HANDSHAKE_TIMEOUT = 67,
  // There was an error encountered migrating addresses.
  QUIC_ERROR_MIGRATING_ADDRESS = 26,
  // There was an error encountered migrating port only.
  QUIC_ERROR_MIGRATING_PORT = 86,
  // There was an error while writing to the socket.
  QUIC_PACKET_WRITE_ERROR = 27,
  // There was an error while reading from the socket.
  QUIC_PACKET_READ_ERROR = 51,
  // We received a STREAM_FRAME with no data and no fin flag set.
  QUIC_EMPTY_STREAM_FRAME_NO_FIN = 50,
  // We received invalid data on the headers stream.
  QUIC_INVALID_HEADERS_STREAM_DATA = 56,
  // The peer received too much data, violating flow control.
  QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA = 59,
  // The peer sent too much data, violating flow control.
  QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA = 63,
  // The peer received an invalid flow control window.
  QUIC_FLOW_CONTROL_INVALID_WINDOW = 64,
  // The connection has been IP pooled into an existing connection.
  QUIC_CONNECTION_IP_POOLED = 62,
  // The connection has too many outstanding sent packets.
  QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS = 68,
  // The connection has too many outstanding received packets.
  QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS = 69,
  // The quic connection has been cancelled.
  QUIC_CONNECTION_CANCELLED = 70,
  // Disabled QUIC because of high packet loss rate.
  QUIC_BAD_PACKET_LOSS_RATE = 71,
  // Disabled QUIC because of too many PUBLIC_RESETs post handshake.
  QUIC_PUBLIC_RESETS_POST_HANDSHAKE = 73,
  // Disabled QUIC because of too many timeouts with streams open.
  QUIC_TIMEOUTS_WITH_OPEN_STREAMS = 74,
  // Closed because we failed to serialize a packet.
  QUIC_FAILED_TO_SERIALIZE_PACKET = 75,
  // QUIC timed out after too many RTOs.
  QUIC_TOO_MANY_RTOS = 85,

  // Crypto errors.

  // Hanshake failed.
  QUIC_HANDSHAKE_FAILED = 28,
  // Handshake message contained out of order tags.
  QUIC_CRYPTO_TAGS_OUT_OF_ORDER = 29,
  // Handshake message contained too many entries.
  QUIC_CRYPTO_TOO_MANY_ENTRIES = 30,
  // Handshake message contained an invalid value length.
  QUIC_CRYPTO_INVALID_VALUE_LENGTH = 31,
  // A crypto message was received after the handshake was complete.
  QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE = 32,
  // A crypto message was received with an illegal message tag.
  QUIC_INVALID_CRYPTO_MESSAGE_TYPE = 33,
  // A crypto message was received with an illegal parameter.
  QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER = 34,
  // An invalid channel id signature was supplied.
  QUIC_INVALID_CHANNEL_ID_SIGNATURE = 52,
  // A crypto message was received with a mandatory parameter missing.
  QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND = 35,
  // A crypto message was received with a parameter that has no overlap
  // with the local parameter.
  QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP = 36,
  // A crypto message was received that contained a parameter with too few
  // values.
  QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND = 37,
  // A demand for an unsupport proof type was received.
  QUIC_UNSUPPORTED_PROOF_DEMAND = 94,
  // An internal error occured in crypto processing.
  QUIC_CRYPTO_INTERNAL_ERROR = 38,
  // A crypto handshake message specified an unsupported version.
  QUIC_CRYPTO_VERSION_NOT_SUPPORTED = 39,
  // A crypto handshake message resulted in a stateless reject.
  QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT = 72,
  // There was no intersection between the crypto primitives supported by the
  // peer and ourselves.
  QUIC_CRYPTO_NO_SUPPORT = 40,
  // The server rejected our client hello messages too many times.
  QUIC_CRYPTO_TOO_MANY_REJECTS = 41,
  // The client rejected the server's certificate chain or signature.
  QUIC_PROOF_INVALID = 42,
  // A crypto message was received with a duplicate tag.
  QUIC_CRYPTO_DUPLICATE_TAG = 43,
  // A crypto message was received with the wrong encryption level (i.e. it
  // should have been encrypted but was not.)
  QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT = 44,
  // The server config for a server has expired.
  QUIC_CRYPTO_SERVER_CONFIG_EXPIRED = 45,
  // We failed to setup the symmetric keys for a connection.
  QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED = 53,
  // A handshake message arrived, but we are still validating the
  // previous handshake message.
  QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO = 54,
  // A server config update arrived before the handshake is complete.
  QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE = 65,
  // CHLO cannot fit in one packet.
  QUIC_CRYPTO_CHLO_TOO_LARGE = 90,
  // This connection involved a version negotiation which appears to have been
  // tampered with.
  QUIC_VERSION_NEGOTIATION_MISMATCH = 55,

  // Multipath errors.
  // Multipath is not enabled, but a packet with multipath flag on is received.
  QUIC_BAD_MULTIPATH_FLAG = 79,
  // A path is supposed to exist but does not.
  QUIC_MULTIPATH_PATH_DOES_NOT_EXIST = 91,
  // A path is supposed to be active but is not.
  QUIC_MULTIPATH_PATH_NOT_ACTIVE = 92,

  // IP address changed causing connection close.
  QUIC_IP_ADDRESS_CHANGED = 80,

  // Connection migration errors.
  // Network changed, but connection had no migratable streams.
  QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS = 81,
  // Connection changed networks too many times.
  QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES = 82,
  // Connection migration was attempted, but there was no new network to
  // migrate to.
  QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK = 83,
  // Network changed, but connection had one or more non-migratable streams.
  QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM = 84,

  // Stream frames arrived too discontiguously so that stream sequencer buffer
  // maintains too many gaps.
  QUIC_TOO_MANY_FRAME_GAPS = 93,

  // No error. Used as bound while iterating.
  QUIC_LAST_ERROR = 95,
};

typedef std::array<char, 32> DiversificationNonce;

struct QuicPacketPublicHeader {
  QuicPacketPublicHeader();
  explicit QuicPacketPublicHeader(const QuicPacketPublicHeader& other);
  ~QuicPacketPublicHeader();

  // Universal header. All QuicPacket headers will have a connection_id and
  // public flags.
  QuicConnectionId connection_id;
  QuicConnectionIdLength connection_id_length;
  bool multipath_flag;
  bool reset_flag;
  bool version_flag;
  QuicPacketNumberLength packet_number_length;
  QuicVersionVector versions;
  // nonce contains an optional, 32-byte nonce value. If not included in the
  // packet, |nonce| will be empty.
  DiversificationNonce* nonce;
};

// An integer which cannot be a packet number.
const QuicPacketNumber kInvalidPacketNumber = 0;

// Header for Data packets.
struct QuicPacketHeader {
  QuicPacketHeader();
  explicit QuicPacketHeader(const QuicPacketPublicHeader& header);
  QuicPacketHeader(const QuicPacketHeader& other);

  friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicPacketHeader& s);

  QuicPacketPublicHeader public_header;
  QuicPacketNumber packet_number;
  QuicPathId path_id;
  bool entropy_flag;
  QuicPacketEntropyHash entropy_hash;
  bool fec_flag;
};

struct QuicPublicResetPacket {
  QuicPublicResetPacket();
  explicit QuicPublicResetPacket(const QuicPacketPublicHeader& header);

  QuicPacketPublicHeader public_header;
  QuicPublicResetNonceProof nonce_proof;
  QuicPacketNumber rejected_packet_number;
  IPEndPoint client_address;
};

}  // namespace qnet

#endif // QNET_PROTOCOL_H_