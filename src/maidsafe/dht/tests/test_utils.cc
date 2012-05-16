/* Copyright (c) 2011 maidsafe.net limited
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

#include <algorithm>
#include <bitset>

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/utils.h"
#include "maidsafe/dht/tests/test_utils.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace dht {

namespace test {

const boost::posix_time::milliseconds kNetworkDelay(200);

AsymGetPublicKeyAndValidation::AsymGetPublicKeyAndValidation(
    const asymm::Identity &/*public_key_id*/,
    const asymm::PublicKey &/*public_key*/,
    const asymm::PrivateKey &/*private_key*/)
        : public_key_id_map_(),
          thread_group_() {}

// Immitating a non-blocking function
void AsymGetPublicKeyAndValidation::GetPublicKeyAndValidation(
    const asymm::Identity &public_key_id,
    asymm::GetPublicKeyAndValidationCallback callback) {
  thread_group_.add_thread(
      new boost::thread(
              &AsymGetPublicKeyAndValidation::DummyContactValidationGetter,
              this, public_key_id, callback));
}

void AsymGetPublicKeyAndValidation::Join() {
  thread_group_.join_all();
}

// This method will validate the network lookup for given public_key_id
bool AsymGetPublicKeyAndValidation::AddTestValidation(
    const asymm::Identity &public_key_id,
    const asymm::PublicKey &public_key) {
  auto itr = public_key_id_map_.insert(std::make_pair(public_key_id,
                                                      public_key));
  return itr.second;
}

void AsymGetPublicKeyAndValidation::ClearTestValidationMap() {
  public_key_id_map_.erase(public_key_id_map_.begin(),
                            public_key_id_map_.end());
}

void AsymGetPublicKeyAndValidation::DummyContactValidationGetter(
    asymm::Identity public_key_id,
    asymm::GetPublicKeyAndValidationCallback callback) {
  // Imitating delay in lookup for kNetworkDelay milliseconds
  Sleep(kNetworkDelay);
  auto itr = public_key_id_map_.find(public_key_id);
  if (itr != public_key_id_map_.end())
    callback((*itr).second, "");
  else
    callback(asymm::PublicKey(), "");
}


RoutingTableManipulator::RoutingTableManipulator(uint16_t k)
    : contact_(),
      generated_ids_(),
      routing_table_(new RoutingTable(NodeId(NodeId::kRandomId), k)) {
  generated_ids_.push_back(routing_table_->kThisId_);
}

NodeId RoutingTableManipulator::GenerateUniqueRandomId(
    int common_leading_bits,
    const NodeId &target_id) {
  BOOST_ASSERT(common_leading_bits < kKeySizeBits);
  std::string target;
  if (target_id == NodeId(kZeroId))
    target = kHolderId().ToStringEncoded(NodeId::kBinary);
  else
    target = target_id.ToStringEncoded(NodeId::kBinary);
  std::bitset<kKeySizeBits> target_id_binary_bitset(target);
  NodeId new_node;
  std::string new_node_string;
  bool repeat(true);
  uint16_t times_of_try(0);
  // generate a random ID and make sure it has not been generated previously
  do {
    new_node = NodeId(NodeId::kRandomId);
    if (common_leading_bits >= 0) {
      std::string new_id = new_node.ToStringEncoded(NodeId::kBinary);
      std::bitset<kKeySizeBits> binary_bitset(new_id);
      for (int i(0); i != common_leading_bits; ++i) {
        binary_bitset[kKeySizeBits - i - 1] =
            target_id_binary_bitset[kKeySizeBits - i - 1];
      }
      binary_bitset[kKeySizeBits - common_leading_bits - 1] =
          !target_id_binary_bitset[kKeySizeBits - common_leading_bits - 1];
      new_node_string = binary_bitset.to_string();
      new_node = NodeId(new_node_string, NodeId::kBinary);
    }
    // make sure the new contact not already existed in the routing table
    auto result = std::find(generated_ids_.begin(),
                            generated_ids_.end(),
                            new_node);
    if (result == generated_ids_.end()) {
      generated_ids_.push_back(new_node);
      repeat = false;
    }
    ++times_of_try;
  } while (repeat && (times_of_try < 1000));
  // prevent deadlock, throw out an error message in case of deadlock
  if (times_of_try == 1000)
    EXPECT_LT(1000, times_of_try);
  return new_node;
}

Contact RoutingTableManipulator::ComposeContact(const NodeId &node_id,
                                               const Port &port) {
  transport::Endpoint end_point("127.0.0.1", port);
  std::vector<transport::Endpoint> local_endpoints(1, end_point);
  Contact contact(node_id, end_point, local_endpoints, end_point, false,
                  false, "", asymm::PublicKey(), "");
  return contact;
}

Contact RoutingTableManipulator::ComposeContactWithKey(
    const NodeId &node_id,
    const Port &port,
    const asymm::Keys &rsa_key_pair) {
  std::string ip("127.0.0.1");
  std::vector<transport::Endpoint> local_endpoints;
  transport::Endpoint end_point(ip, port);
  local_endpoints.push_back(end_point);
  Contact contact(node_id, end_point, local_endpoints, end_point, false,
                  false, node_id.String(), rsa_key_pair.public_key, "");
  IP ipa = IP::from_string(ip);
  contact.SetPreferredEndpoint(ipa);
  return contact;
}

void RoutingTableManipulator::PopulateRoutingTable(int count,
                                                   int common_leading_bits) {
  for (int i(0); i != count; ++i) {
    NodeId contact_id = GenerateUniqueRandomId(common_leading_bits);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_->AddContact(contact, RankInfoPtr(new transport::Info));
    routing_table_->SetValidated(contact_id, true);
  }
}

void RoutingTableManipulator::GetContact(const NodeId &node_id,
                                        Contact *contact) {
  std::vector<Contact> excludes, close_contacts;
  routing_table_->GetCloseContacts(node_id, 1, excludes, close_contacts);
  if (!close_contacts.empty() && close_contacts.front().node_id() == node_id)
    *contact = close_contacts.front();
}

std::vector<RoutingTableContact> RoutingTableManipulator::GetContacts() const {
  boost::mutex::scoped_lock lock(routing_table_->mutex_);
  return routing_table_->contacts_;
}

bool RoutingTableManipulator::GetRoutingTableContact(
    const NodeId &node_id,
    RoutingTableContact &routing_table_contact) const {
  boost::mutex::scoped_lock lock(routing_table_->mutex_);
  auto itr(std::find_if(routing_table_->contacts_.begin(),
                        routing_table_->contacts_.end(),
                        [&node_id](const RoutingTableContact &rt_contact) {
    return rt_contact.contact.node_id() == node_id;
  }));

  if (itr == routing_table_->contacts_.end())
    return false;

  routing_table_contact = *itr;
  return true;
}

RoutingTable::UnvalidatedContacts
    RoutingTableManipulator::GetUnvalidatedContacts() const {
  boost::mutex::scoped_lock lock(routing_table_->mutex_);
  return routing_table_->unvalidated_contacts_;
}

void RoutingTableManipulator::Reset() {
  generated_ids_.clear();
  generated_ids_.push_back(routing_table_->kThisId_);
  boost::mutex::scoped_lock lock(routing_table_->mutex_);
  routing_table_->contacts_.clear();
  routing_table_->unvalidated_contacts_.clear();
  routing_table_->own_bucket_index_ = 0;
}



KeyValueSignature MakeKVS(const asymm::Keys &rsa_key_pair,
                          const size_t &value_size,
                          std::string key,
                          std::string value) {
  if (key.empty())
    key = crypto::Hash<crypto::SHA512>(RandomString(1024));
  if (value.empty()) {
    value.reserve(value_size);
    std::string temp = RandomString((value_size > 1024) ? 1024 : value_size);
    while (value.size() < value_size)
      value += temp;
    value = value.substr(0, value_size);
  }
  std::string signature;
  asymm::Sign(value, rsa_key_pair.private_key, &signature);
  return KeyValueSignature(key, value, signature);
}

KeyValueTuple MakeKVT(const asymm::Keys &rsa_key_pair,
                      const size_t &value_size,
                      const bptime::time_duration &ttl,
                      std::string key,
                      std::string value) {
  if (key.empty())
    key = crypto::Hash<crypto::SHA512>(RandomString(1024));
  if (value.empty()) {
    value.reserve(value_size);
    std::string temp = RandomString((value_size > 1024) ? 1024 : value_size);
    while (value.size() < value_size)
      value += temp;
    value = value.substr(0, value_size);
  }
  std::string signature;
  asymm::Sign(value, rsa_key_pair.private_key, &signature);
  bptime::ptime now = bptime::microsec_clock::universal_time();
  bptime::ptime expire_time = now + ttl;
  bptime::ptime refresh_time = now + bptime::minutes(30);
  std::string request = RandomString(1024);
  std::string req_sig;
  asymm::Sign(request, rsa_key_pair.private_key, &req_sig);
  return KeyValueTuple(KeyValueSignature(key, value, signature),
                       expire_time, refresh_time,
                       RequestAndSignature(request, req_sig), false);
}

protobuf::StoreRequest MakeStoreRequest(
    const Contact &sender,
    const KeyValueSignature &key_value_signature) {
  protobuf::StoreRequest store_request;
  store_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
  store_request.set_key(key_value_signature.key);
  store_request.mutable_signed_value()->set_signature(
      key_value_signature.signature);
  store_request.mutable_signed_value()->set_value(key_value_signature.value);
  store_request.set_ttl(3600*24);
  return store_request;
}

protobuf::DeleteRequest MakeDeleteRequest(
    const Contact &sender,
    const KeyValueSignature &key_value_signature) {
  protobuf::DeleteRequest delete_request;
  delete_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
  delete_request.set_key(key_value_signature.key);
  delete_request.mutable_signed_value()->set_signature(
      key_value_signature.signature);
  delete_request.mutable_signed_value()->set_value(key_value_signature.value);
  return delete_request;
}

void JoinNetworkLookup(KeyPairPtr key_pair) {
  AsymGPKPtr key_pair_gpkv(new AsymGetPublicKeyAndValidation(
      key_pair->identity,
      key_pair->public_key,
      key_pair->private_key));
  key_pair_gpkv->Join();
}

bool AddTestValidation(KeyPairPtr key_pair,
                       std::string public_key_id,
                       asymm::PublicKey public_key) {
  AsymGPKPtr key_pair_gpkv(new AsymGetPublicKeyAndValidation(
      key_pair->identity,
      key_pair->public_key,
      key_pair->private_key));
  return key_pair_gpkv->AddTestValidation(public_key_id, public_key);
}

void AddContact(std::shared_ptr<RoutingTable> routing_table,
                const Contact &contact,
                const RankInfoPtr rank_info) {
  routing_table->AddContact(contact, rank_info);
  routing_table->SetValidated(contact.node_id(), true);
}

void SortIds(const NodeId &target_key, std::vector<NodeId> *node_ids) {
  if (!node_ids || node_ids->empty())
    return;
  std::sort(node_ids->begin(), node_ids->end(),
      std::bind(static_cast<bool(*)(const NodeId&, // NOLINT
                                    const NodeId&,
                                    const NodeId&)>(&NodeId::CloserToTarget),
                args::_1, args::_2, target_key));
}

bool WithinKClosest(const NodeId &node_id,
                    const Key &target_key,
                    std::vector<NodeId> node_ids,
                    const uint16_t &k) {
  // Put the k closest first (and sorted) in the vector.
  std::function<bool(const NodeId&, const NodeId&)> predicate = // NOLINT (Fraser)
      std::bind(static_cast<bool(*)(const NodeId&, const NodeId&, // NOLINT (Fraser)
                                    const NodeId&)>(&NodeId::CloserToTarget),
                args::_1, args::_2, target_key);
  std::partial_sort(node_ids.begin(), node_ids.begin() + k, node_ids.end(),
                    predicate);
  return (std::find(node_ids.begin(), node_ids.begin() + k, node_id) !=
          node_ids.begin() + k);
}

void ExecDummyContactValidationGetter(
    asymm::Identity /*identity*/,
    asymm::GetPublicKeyAndValidationCallback callback) {
  // Imitating delay in lookup for kNetworkDelay milliseconds
  Sleep(kNetworkDelay);
  callback(asymm::PublicKey(), asymm::ValidationToken());
}

void DummyContactValidationGetter(
    asymm::Identity identity,
    asymm::GetPublicKeyAndValidationCallback callback) {
  boost::thread(&ExecDummyContactValidationGetter, identity, callback);
}

bool ValidateFalse(const asymm::PlainText& /*plain_text*/,
                   const asymm::Signature& /*signature*/,
                   const asymm::PublicKey& /*public_key*/) {
  return false;
}


}  // namespace test

}  // namespace dht

}  // namespace maidsafe
