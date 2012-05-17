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

#include "maidsafe/dht/routing_table.h"

#include <algorithm>
#include <bitset>

#include "maidsafe/dht/config.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/utils.h"
#include "maidsafe/dht/log.h"

namespace maidsafe {

namespace dht {

namespace {

const auto kToContact([](const RoutingTableContact &routing_table_contact) {  // NOLINT (Fraser)
                        return routing_table_contact.contact; });  // NOLINT (Fraser)

// Returns common leading bit count
int GetKBucketIndex(const NodeId &holder_id, const NodeId &node_id) {
  std::string holder_raw_id(holder_id.String());
  std::string node_raw_id(node_id.String());
  uint16_t byte_index(0);
  while (byte_index != kKeySizeBytes) {
    if (holder_raw_id[byte_index] != node_raw_id[byte_index]) {
      std::bitset<8> holder_byte(static_cast<int>(holder_raw_id[byte_index]));
      std::bitset<8> node_byte(static_cast<int>(node_raw_id[byte_index]));
      size_t bit_index(0);
      while (bit_index != 8U) {
        if (holder_byte[7U - bit_index] != node_byte[7U - bit_index])
          break;
        ++bit_index;
      }
      return static_cast<int>((8 * byte_index) + bit_index);
    }
    ++byte_index;
  }
  return static_cast<int>((8 * kKeySizeBytes) - 1);
}

}  // unnamed namespace

RoutingTableContact::RoutingTableContact(const Contact &contact,
                                         const NodeId &holder_id,
                                         const RankInfoPtr &rank_info)
      : contact(contact),
        num_failed_rpcs(0),
        k_bucket_index(GetKBucketIndex(holder_id, contact.node_id())),
        last_seen(bptime::microsec_clock::universal_time()),
        rank_info(rank_info) {}


RoutingTable::RoutingTable(const NodeId &this_id, const uint16_t &k)
    : kThisId_(this_id),
      kDebugId_(DebugId(kThisId_)),
      k_(k),
      contacts_(),
      unvalidated_contacts_([](const RoutingTableContact &lhs,
                               const RoutingTableContact &rhs) {
                                   return lhs.contact.node_id() <
                                          rhs.contact.node_id();
                            }),
      ping_oldest_contact_(),
      validate_contact_(),
      ping_down_contact_(),
      own_bucket_index_(0),
      mutex_() {
  contacts_.reserve(35 * k);
}

RoutingTable::~RoutingTable() {
  boost::mutex::scoped_lock lock(mutex_);
  unvalidated_contacts_.clear();
  contacts_.clear();
}

int RoutingTable::AddContact(const Contact &contact, RankInfoPtr rank_info) {
  // If the contact has the same ID as the holder, return directly
  if (contact.node_id() == kThisId_) {
    DLOG(WARNING) << kDebugId_ << ": Can't add own ID to routing table.";
    return kOwnIdNotIncludable;
  }

  // Check if the contact is already in the routing table; if so, set its last
  // seen time to now (will bring it to the top) and reset its failed RPC count.
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(Find(contact.node_id()));
  if (itr != contacts_.end()) {
    (*itr).last_seen = bptime::microsec_clock::universal_time();
    (*itr).num_failed_rpcs = 0;
    return kSuccess;
  }

  // Put the contact into the unvalidated contacts container.
  RoutingTableContact routing_table_contact(contact, kThisId_, rank_info);
  if (unvalidated_contacts_.insert(routing_table_contact).second) {
    // Fire the signal to validate the contact.
    lock.unlock();
    validate_contact_(contact);
  }

  return kSuccess;
}

void RoutingTable::GetCloseContacts(
    const NodeId &target_id,
    const size_t &count,
    std::vector<Contact> exclude_contacts,
    std::vector<Contact> &close_contacts) {
  // Sort just enough contacts to allow for excluding as required.
  boost::mutex::scoped_lock lock(mutex_);
  size_t sort_size(std::min(count + exclude_contacts.size(), contacts_.size()));
  std::partial_sort(contacts_.begin(),
                    contacts_.begin() + sort_size,
                    contacts_.end(),
                    [&target_id](const RoutingTableContact &lhs,
                                 const RoutingTableContact &rhs) {
    return NodeId::CloserToTarget(lhs.contact.node_id(),
                                  rhs.contact.node_id(),
                                  target_id);
  });

  // Copy sorted contacts_ to close_contacts.
  close_contacts.resize(sort_size);
  std::transform(contacts_.begin(),
                 contacts_.begin() + sort_size,
                 close_contacts.begin(),
                 kToContact);

  // Remove exclude_contacts from close_contacts.
  auto comparison([&target_id](const Contact &lhs, const Contact &rhs) {
    return NodeId::CloserToTarget(lhs.node_id(), rhs.node_id(), target_id);
  });
  std::sort(exclude_contacts.begin(),
            exclude_contacts.end(),
            comparison);
  auto included_end_itr(std::set_difference(close_contacts.begin(),
                                            close_contacts.end(),
                                            exclude_contacts.begin(),
                                            exclude_contacts.end(),
                                            close_contacts.begin(),
                                            comparison));

  // Prune to correct size.
  auto begin_erase_itr(std::min(
      included_end_itr,
      (close_contacts.size() > count ?
          close_contacts.begin() + count :
          close_contacts.end())));
  close_contacts.erase(begin_erase_itr, close_contacts.end());
}

std::vector<RoutingTableContact>::iterator RoutingTable::Find(
    const NodeId &node_id) {
  return std::find_if(contacts_.begin(),
                      contacts_.end(),
                      [&node_id]
                          (const RoutingTableContact &routing_table_contact) {
    return routing_table_contact.contact.node_id() == node_id;
  });
}

void RoutingTable::Downlist(const NodeId &node_id) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(Find(node_id));
  if (itr != contacts_.end())
    ping_down_contact_((*itr).contact);
}

int RoutingTable::UpdateRankInfo(const NodeId &node_id,
                                 RankInfoPtr new_rank_info) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(Find(node_id));
  if (itr == contacts_.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(node_id);
    return kFailedToFindContact;
  }
  (*itr).rank_info = new_rank_info;
  return kSuccess;
}

int RoutingTable::SetValidated(const NodeId &node_id, bool validated) {
  boost::mutex::scoped_lock lock(mutex_);
  auto unvalidated_itr = unvalidated_contacts_.begin();
  while (unvalidated_itr != unvalidated_contacts_.end()) {
    if ((*unvalidated_itr).contact.node_id() == node_id)
      break;
    else
      ++unvalidated_itr;
  }

  auto itr(Find(node_id));
  if (unvalidated_itr != unvalidated_contacts_.end()) {
    if (validated && (itr == contacts_.end()))
      InsertContact(*unvalidated_itr);
    unvalidated_contacts_.erase(unvalidated_itr);
    return kSuccess;
  }

  if (itr == contacts_.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(node_id);
    return kFailedToFindContact;
  }
  if (!validated) {
    DLOG(WARNING) << kDebugId_ << ": Node " << DebugId(node_id)
                  << " removed from routing table - failed to validate.  "
                  << contacts_.size() << " contacts.";
    contacts_.erase(itr);
  }

  return kSuccess;
}

void RoutingTable::InsertContact(
    const RoutingTableContact &contact_to_insert) {
  // Get the new contact's fellow k-bucket contacts.  All contacts with k-bucket
  // index >= own_bucket_index_ are effectively in the holder's own k-bucket.
  auto bucket_end_itr(
      std::partition(contacts_.begin(),
                     contacts_.end(),
                     [&](const RoutingTableContact &rt_contact)->bool {
    if (contact_to_insert.k_bucket_index < own_bucket_index_)
      return contact_to_insert.k_bucket_index == rt_contact.k_bucket_index;
    else
      return rt_contact.k_bucket_index >= own_bucket_index_;
  }));
  BOOST_ASSERT(std::distance(contacts_.begin(), bucket_end_itr) <= k_);

  // If the k-bucket isn't full, insert and return.
  if (std::distance(contacts_.begin(), bucket_end_itr) < k_)
    return contacts_.push_back(contact_to_insert);

  // If the new contact belongs in the same bucket as owner, split it and try to
  // insert again.
  if (contact_to_insert.k_bucket_index >= own_bucket_index_) {
    ++own_bucket_index_;
    return InsertContact(contact_to_insert);
  }

  // Invoke "Force k"; if the new contact is within the k closest to the holder,
  // replace the kth closest contact with the new contact and return.
  std::nth_element(contacts_.begin(),
                   contacts_.begin() + k_ - 1,
                   contacts_.end(),
                   [&](const RoutingTableContact &lhs,
                       const RoutingTableContact &rhs) {
    return NodeId::CloserToTarget(lhs.contact.node_id(),
                                  rhs.contact.node_id(),
                                  kThisId_);
  });
  if (NodeId::CloserToTarget(contact_to_insert.contact.node_id(),
                             (*(contacts_.begin() + k_ - 1)).contact.node_id(),
                             kThisId_)) {
    *(contacts_.begin() + k_ - 1) = contact_to_insert;
    return;
  }

  // Finally, the new contact is not in same bucket as the holder's own, so
  // fire ping_oldest_contact_ signal and return.  The slot will take care of
  // adding the new contact after dropping the old contact if it doesn't respond
  // or resetting the last-seen time for the old contact if it does respond.

  // Get the new contact's fellow k-bucket contacts.
  BOOST_ASSERT(contact_to_insert.k_bucket_index < own_bucket_index_);
  bucket_end_itr = (
      std::partition(contacts_.begin(),
                     contacts_.end(),
                     [&](const RoutingTableContact &rt_contact) {
    return contact_to_insert.k_bucket_index == rt_contact.k_bucket_index;
  }));
  BOOST_ASSERT(std::distance(contacts_.begin(), bucket_end_itr) == k_);
  // Move the least recently seen contact to the start of contacts_.
  std::nth_element(contacts_.begin(),
                   contacts_.begin(),
                   contacts_.begin() + k_,
                   [&](const RoutingTableContact &lhs,
                       const RoutingTableContact &rhs) {
    return lhs.last_seen > rhs.last_seen;
  });
  ping_oldest_contact_((*contacts_.begin()).contact,
                       contact_to_insert.contact,
                       contact_to_insert.rank_info);
}

int RoutingTable::IncrementFailedRpcCount(const NodeId &node_id) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(Find(node_id));
  if (itr == contacts_.end()) {
    DLOG(INFO) << kDebugId_ << ": Failed to find node " << DebugId(node_id);
    return kFailedToFindContact;
  }

  if (++(*itr).num_failed_rpcs > kFailedRpcTolerance) {
    contacts_.erase(itr);
    DLOG(INFO) << kDebugId_ << ": Removed node " << DebugId(node_id) << ".  "
               << contacts_.size() << " contacts.";
  } else {
    DLOG(INFO) << kDebugId_ << ": Incremented failed RPC count for node "
                << DebugId(node_id) << " to " << (*itr).num_failed_rpcs;
  }
  return kSuccess;
}

void RoutingTable::GetBootstrapContacts(std::vector<Contact> *contacts) {
  BOOST_ASSERT(contacts);
  boost::mutex::scoped_lock lock(mutex_);
  auto it(std::partition(contacts_.begin(),
                         contacts_.end(),
                         [](const RoutingTableContact &routing_table_contact) {
    return routing_table_contact.contact.IsDirectlyConnected();
  }));

  contacts->resize(std::distance(contacts_.begin(), it));
  std::transform(contacts_.begin(), it, contacts->begin(), kToContact);
}

RankInfoPtr RoutingTable::GetLocalRankInfo(const Contact &contact) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(Find(contact.node_id()));
  if (itr == contacts_.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(contact);
    return RankInfoPtr();
  }
  return (*itr).rank_info;
}

void RoutingTable::GetAllContacts(std::vector<Contact> *contacts) {
  BOOST_ASSERT(contacts);
  boost::mutex::scoped_lock lock(mutex_);
  contacts->resize(contacts_.size());
  std::transform(contacts_.begin(), contacts_.end(), contacts->begin(),
                 kToContact);
}

PingOldestContact& RoutingTable::ping_oldest_contact() {
  return ping_oldest_contact_;
}

ValidateContact& RoutingTable::validate_contact() {
  return validate_contact_;
}

PingDownContact& RoutingTable::ping_down_contact() {
  return ping_down_contact_;
}

}  // namespace dht

}  // namespace maidsafe
