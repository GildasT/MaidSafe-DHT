/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef MAIDSAFE_DHT_ROUTING_TABLE_H_
#define MAIDSAFE_DHT_ROUTING_TABLE_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/signals2/signal.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/node_id.h"


namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport { struct Info; }

namespace dht {

namespace test { class RoutingTableManipulator; }

struct RoutingTableContact {
  RoutingTableContact(const Contact &contact,
                      const NodeId &holder_id,
                      const std::shared_ptr<transport::Info> &rank_info);
  Contact contact;
  int num_failed_rpcs, k_bucket_index;
  bptime::ptime last_seen;
  std::shared_ptr<transport::Info> rank_info;
};

typedef boost::signals2::signal<
    void(const Contact&,
         const Contact&,
         std::shared_ptr<transport::Info>)> PingOldestContact;

typedef boost::signals2::signal<void(const Contact&)> ValidateContact,
                                                      PingDownContact;

/** Object containing a node's Kademlia Routing Table and all its contacts.
 *  @class RoutingTable */
class RoutingTable {
 public:
  /** Constructor.  To create a routing table, in all cases the node ID and
   *  k closest contacts parameter must be provided.
   *  @param[in] this_id The routing table holder's Kademlia ID.
   *  @param[in] k Kademlia constant k. */
  RoutingTable(const NodeId &this_id, const uint16_t &k);
  /** Destructor. */
  ~RoutingTable();
  /** Add the given contact to the correct k-bucket; if it already
   *  exists, its status will be updated.  If the given k-bucket is full and not
   *  splittable, the signal ping_oldest_contact_ will be fired which will
   *  ultimately resolve whether the contact is added or not.
   *  @param[in] contact The new contact which needs to be added.
   *  @param[in] rank_info The contact's rank_info.
   *  @return Return code 0 for success, otherwise failure. */
  int AddContact(const Contact &contact,
                 std::shared_ptr<transport::Info> rank_info);
  /** Finds a number of known nodes closest to the target node in the current
   *  routing table, sorted by closeness to target_id.
   *  @param[in] target_id The Kademlia ID of the target node.
   *  @param[in] count Number of closest nodes looking for.
   *  @param[in] exclude_contacts List of contacts that shall be excluded.
   *  @param[out] close_contacts Result of the find closest contacts. */
  void GetCloseContacts(const NodeId &target_id,
                        const size_t &count,
                        std::vector<Contact> exclude_contacts,
                        std::vector<Contact> &close_contacts);
  /** Checks if node_id is in routing table, and if it is, fires
   *  ping_down_contact_ to see whether the contact is actually offline.*/
  void Downlist(const NodeId &node_id);
  /** Update one node's rank info.
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] rank_info The new value of the rank info.
   *  @return Return code 0 for success, otherwise failure. */
  int UpdateRankInfo(const NodeId &node_id,
                     std::shared_ptr<transport::Info> rank_info);
  /** Set one node's validation status.
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] validated The validation status.
   *  @return Return code 0 for success, otherwise failure. */
  int SetValidated(const NodeId &node_id, bool validated);
  /** Increase one node's failedRPC counter by one.  If the count exceeds the
   *  value of kFailedRpcTolerance, the contact is removed from the routing
   *  table.
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @return Return code 0 for success, otherwise failure. */
  int IncrementFailedRpcCount(const NodeId &node_id);
  /** Get the routing table holder's direct-connected nodes.
   *  For a direct-connected node, there must be no rendezvous endpoint,
   *  but either of tcp443 or tcp80 may be true.
   *  @param[out] contacts The result of all directly connected contacts. */
  void GetBootstrapContacts(std::vector<Contact> *contacts);
  /** Get the local RankInfo of the contact
   *  @param[in] contact The contact to find
   *  @return The localRankInfo of the contact */
  std::shared_ptr<transport::Info> GetLocalRankInfo(const Contact &contact);
  /** Get all contacts in the routing table
   *  @param[out] contacts All contacts in the routing table */
  void GetAllContacts(std::vector<Contact> *contacts);
  /** Getter.
   *  @return The ping_oldest_contact_ signal. */
  PingOldestContact& ping_oldest_contact();
  /** Getter.
   *  @return The validate_contact_ signal. */
  ValidateContact& validate_contact();
  /** Getter.
   *  @return The ping_down_contact_ signal. */
  PingDownContact& ping_down_contact();

  friend class test::RoutingTableManipulator;

 private:
  typedef std::set<RoutingTableContact,
                   bool(*)(const RoutingTableContact&,        // NOLINT (Fraser)
                           const RoutingTableContact&)> UnvalidatedContacts;

  void InsertContact(const RoutingTableContact &contact_to_insert);
  std::vector<RoutingTableContact>::iterator Find(const NodeId &node_id);

  /** Holder's Kademlia ID */
  const NodeId kThisId_;
  /** Holder's Kademlia ID held as a human readable string for debugging */
  const std::string kDebugId_;
  /** Kademlia k */
  const uint16_t k_;
  /** Containers of all validated contacts and unvalidated contacts */
  std::vector<RoutingTableContact> contacts_;
  UnvalidatedContacts unvalidated_contacts_;
  /** Signal to be fired when k-bucket is full and cannot be split.  In signal
   *  signature, last-seen contact is first, then new contact and new contact's
   *  rank info.  Slot should ping the old contact and if successful, should
   *  call AddContact for the old contact, or if unsuccessful, should call
   *  IncrementFailedRpcCount for the old contact.  If this removes the old
   *  contact, the slot should then call AddContact for the new contact. */
  PingOldestContact ping_oldest_contact_;
  /** Signal to be fired when adding a new contact. The contact will be added
   *  into the routing table directly, but having the Validated tag to be false.
   *  The new added contact will be passed as signal signature. Slot should
   *  validate the contact, then set the corresponding Validated tag in the
   *  routing table or to remove the contact from the routing table, if
   *  validation failed. */
  ValidateContact validate_contact_;
  /** Signal to be fired when we receive notification that a contact we hold is
   *  offline.  In signal signature, contact is first, then contact's rank info.
   *  Slot should ping the contact and if successful, should call AddContact for
   *  the contact, or if unsuccessful, should call IncrementFailedRpcCount for
   *  the down contact twice (once to represent the notifier's failed attempt to
   *  reach the node). */
  PingDownContact ping_down_contact_;
  int own_bucket_index_;
  boost::mutex mutex_;
};

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_ROUTING_TABLE_H_
