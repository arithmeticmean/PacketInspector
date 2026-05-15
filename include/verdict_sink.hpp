#pragma once

#include "packet.hpp"

#include <vector>

// Where decided packets go. NFQueue implements this by queueing them for its
// verdict thread; tests substitute a fake that just records what it was given.
//
// Implementations take ownership. Every packet handed to a sink must end up
// verdicted -- one that doesn't holds a kernel queue slot for the lifetime of
// the process and hangs its connection.
class VerdictSink {
public:
  virtual ~VerdictSink() = default;

  virtual void submit(Packet &&pkt, Verdict v) = 0;

  // Batch form, for a whole flow at once. Leaves `pkts` empty.
  virtual void submit(std::vector<Packet> &&pkts, Verdict v) = 0;
};
