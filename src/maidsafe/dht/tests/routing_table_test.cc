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

#include <bitset>
#include <memory>

#include "boost/lexical_cast.hpp"
#include "boost/thread/thread.hpp"
#include "boost/thread/barrier.hpp"
#include "boost/asio/io_service.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/transport/utils.h"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/contact.h"
#include "maidsafe/dht/routing_table.h"
#include "maidsafe/dht/return_codes.h"
#include "maidsafe/dht/node_id.h"
#include "maidsafe/dht/tests/test_utils.h"

namespace maidsafe {

namespace dht {

namespace test {

static const uint16_t kThreadBarrierSize = 2;

class RoutingTableTest : public RoutingTableManipulator,
                         public testing::TestWithParam<int> {
 public:
  RoutingTableTest()
      : RoutingTableManipulator(static_cast<uint16_t>(GetParam())),
        rank_info_(),
        k_(static_cast<uint16_t>(GetParam())),
        contact_(ComposeContact(NodeId(NodeId::kRandomId), 6101)),
        thread_barrier_(new boost::barrier(kThreadBarrierSize)) {}

  // Methods for multithreaded test
  void DoAddContact(Contact contact) {
    thread_barrier_->wait();
    routing_table_->AddContact(contact, rank_info_);
    routing_table_->SetValidated(contact.node_id(), true);
  }

  void DoGetCloseContacts(const size_t &count) {
    NodeId target_id(GenerateUniqueRandomId(12));
    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    thread_barrier_->wait();
    routing_table_->GetCloseContacts(target_id, count, exclude_contacts,
                                    close_contacts);
    EXPECT_EQ(size_t(count), close_contacts.size());
  }

  void DoUpdateRankInfo(NodeId node_id, RankInfoPtr rank_info) {
    thread_barrier_->wait();
    EXPECT_EQ(0, routing_table_->UpdateRankInfo(node_id, rank_info));
  }

  void DoAddRemoveContact(Contact contact) {
    routing_table_->AddContact(contact, rank_info_);
    thread_barrier_->wait();
    for (int i = 0; i <= kFailedRpcTolerance ; ++i)
      routing_table_->IncrementFailedRpcCount(contact.node_id());
  }

 protected:
  void AddContact(const Contact& contact) {
    routing_table_->AddContact(contact, rank_info_);
    routing_table_->SetValidated(contact.node_id(), true);
  }

  void FillContactToRoutingTable() {
    for (uint16_t i = 0; i < k_; ++i) {
      Contact contact = ComposeContact(NodeId(NodeId::kRandomId), i + 6111);
      (i == (k_ - 1)) ? AddContact(contact_) : AddContact(contact);
    }
    EXPECT_EQ(k_, GetContacts().size());
  }

  size_t GetKBucketCount() {
    return own_bucket_index() + 1;
  }

  size_t GetKBucketSizeForKey(int k_bucket_index) {
    auto contacts(GetContacts());
    int own_bucket_ind(own_bucket_index());
    size_t count(
        std::count_if(contacts.begin(),
                      contacts.end(),
                      [k_bucket_index, own_bucket_ind]
                          (const RoutingTableContact &rt_contact)->bool {
      if (k_bucket_index < own_bucket_ind)
        return rt_contact.k_bucket_index == k_bucket_index;
      else
        return rt_contact.k_bucket_index >= k_bucket_index;
    }));
    return count;
  }

  RankInfoPtr rank_info_;
  uint16_t k_;
  Contact contact_;
  std::shared_ptr<boost::barrier> thread_barrier_;
};


class RoutingTableSingleKTest : public RoutingTableTest {
 public:
  RoutingTableSingleKTest() : RoutingTableTest() {}
};


INSTANTIATE_TEST_CASE_P(VariantKValues, RoutingTableTest,
                        testing::Range(2, 21));

INSTANTIATE_TEST_CASE_P(SingleKValue, RoutingTableSingleKTest,
                        testing::Values(2, 16));


TEST_P(RoutingTableTest, BEH_Constructor) {
  ASSERT_EQ(0U, GetContacts().size());
  ASSERT_EQ(1U, GetKBucketCount());
}

TEST_P(RoutingTableTest, BEH_SetValidated) {
  // Note: this test case might need to be modified once the signal slot
  // is connected (i.e. there is handler to set the Validated tag automatically)

  // Set one entry to be validated
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5001);
  routing_table_->AddContact(contact, rank_info_);
  ASSERT_EQ(1U, GetUnvalidatedContacts().size());
  ASSERT_EQ(0U, GetContacts().size());
  routing_table_->SetValidated(contact_id, true);
  ASSERT_EQ(0U, GetUnvalidatedContacts().size());
  ASSERT_EQ(1U, GetContacts().size());

  // Set the entry to invalid
  routing_table_->SetValidated(contact_id, false);
  ASSERT_EQ(0U, GetUnvalidatedContacts().size());
  ASSERT_EQ(0U, GetContacts().size());

  // Add the entry again
  routing_table_->AddContact(contact, rank_info_);
  ASSERT_EQ(1U, GetUnvalidatedContacts().size());
  ASSERT_EQ(0U, GetContacts().size());

  // Set the entry to invalid, this shall remove the entry
  routing_table_->SetValidated(contact_id, false);
  ASSERT_EQ(0U, GetUnvalidatedContacts().size());
  ASSERT_EQ(0U, GetContacts().size());
}

TEST_P(RoutingTableTest, BEH_AddContact) {
  // Try to add the holder itself into the routing table
  contact_ = ComposeContact(kHolderId(), 5000);
  AddContact(contact_);
  EXPECT_TRUE(GetContacts().empty());

  // Test update NumFailedRpc and LastSeen when new contact already exists
  NodeId contact_id = GenerateUniqueRandomId(4);
  contact_ = ComposeContact(contact_id, 5000);
  AddContact(contact_);
  routing_table_->IncrementFailedRpcCount(contact_id);
  RoutingTableContact routing_table_contact(contact_, NodeId(), RankInfoPtr());
  ASSERT_TRUE(GetRoutingTableContact(contact_.node_id(),
                                     routing_table_contact));

  ASSERT_EQ(1U, routing_table_contact.num_failed_rpcs);
  bptime::ptime old_last_seen(routing_table_contact.last_seen);
  Sleep(boost::posix_time::milliseconds(1));
  AddContact(contact_);
  ASSERT_TRUE(GetRoutingTableContact(contact_.node_id(),
                                     routing_table_contact));
  ASSERT_EQ(0U, routing_table_contact.num_failed_rpcs);
  ASSERT_LT(old_last_seen, routing_table_contact.last_seen);

  Reset();
  uint16_t i(0);
  // Create a list of Contacts having 3 common leading bits with the holder
  // and add them into the routing table
  for (; i < k_; ++i) {
    contact_id = GenerateUniqueRandomId(3);
    AddContact(ComposeContact(contact_id, (5000 + i)));
    EXPECT_EQ(i + 1, GetContacts().size());
    EXPECT_EQ(1U, GetKBucketCount());
  }
  EXPECT_EQ(k_, GetKBucketSizeForKey(0));

  // Test Split Bucket
  // create a contact having 1 common leading bit with the holder
  // and add it into the routing table
  contact_id = GenerateUniqueRandomId(1);
  Contact contact = ComposeContact(contact_id, 5000 + i);
  AddContact(contact);
  ++i;
  EXPECT_EQ(i, GetContacts().size());

  // all k_ contacts having 3 common leading bits sit in the kbucket
  // covering 2-512
  if (3U != GetKBucketCount())
    EXPECT_EQ(3U, GetKBucketCount());
  EXPECT_EQ(0U, GetKBucketSizeForKey(0));
  EXPECT_EQ(1U, GetKBucketSizeForKey(1));
  EXPECT_EQ(k_, GetKBucketSizeForKey(2));

  // Test Split Bucket Advanced
  // create a contact having 5 common leading bits with the holder
  // and add it into the routing table
  contact_id = GenerateUniqueRandomId(5);
  contact = ComposeContact(contact_id, 5000 + i);
  AddContact(contact);
  ++i;
  EXPECT_EQ(i, GetContacts().size());
  EXPECT_EQ(5U, GetKBucketCount());
  EXPECT_EQ(0U, GetKBucketSizeForKey(0));
  EXPECT_EQ(1U, GetKBucketSizeForKey(1));
  EXPECT_EQ(0U, GetKBucketSizeForKey(2));
  EXPECT_EQ(k_, GetKBucketSizeForKey(3));
  EXPECT_EQ(1U, GetKBucketSizeForKey(4));

  {
    // Test ForceK, reject and accept will be tested
    // create a contact having 3 common leading bits with the holder
    // and add it into the routing table
    // this contact shall be now attempting to add into the brother buckets
    // it shall be added (replace a previous one) if close enough or be rejected
    bool replaced(false);
    bool not_replaced(false);
    // To prevent test hanging
    uint16_t times_of_try(0);
    while (((!not_replaced) || (!replaced)) && (times_of_try < 60000)) {
      contact_id = GenerateUniqueRandomId(3);
      contact = ComposeContact(contact_id, (5000 + i + times_of_try));
      AddContact(contact);
      EXPECT_EQ(i, GetContacts().size());
      EXPECT_EQ(5U, GetKBucketCount());
      EXPECT_EQ(0U, GetKBucketSizeForKey(0));
      EXPECT_EQ(1U, GetKBucketSizeForKey(1));
      EXPECT_EQ(0U, GetKBucketSizeForKey(2));
      EXPECT_EQ(k_, GetKBucketSizeForKey(3));
      EXPECT_EQ(1U, GetKBucketSizeForKey(4));

      Contact result;
      GetContact(contact_id, &result);
      // Make sure both replace and reject situation covered in ForceK sim test
      if (result != Contact()) {
        replaced = true;
      } else {
        not_replaced = true;
      }
      ++times_of_try;
    }
    ASSERT_GT(60000, times_of_try);
  }
}

TEST_P(RoutingTableTest, BEH_AddContactForRandomCommonLeadingBits) {
  // Compose contact with random common_leading_bits
  for (uint16_t i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(-1);
    Contact contact = ComposeContact(node_id, 5111 + i);
    AddContact(contact);
  }

  NodeId node_id = GenerateUniqueRandomId(10);
  Contact contact = ComposeContact(node_id, 5113);
  AddContact(contact);
  size_t num_of_contacts(0);
  for (uint16_t i = 0; i < GetKBucketCount(); ++i) {
    size_t contacts_in_bucket = GetKBucketSizeForKey(i);
    EXPECT_GE(k_, contacts_in_bucket);
    num_of_contacts += contacts_in_bucket;
  }
  EXPECT_EQ(num_of_contacts, GetContacts().size());
  EXPECT_LT(1U, GetKBucketCount());
}

TEST_P(RoutingTableSingleKTest, FUNC_AddContactPerformanceBalanced) {
  // the last four common bits will not split kbucket
  for (int common_head = 0; common_head < 100; ++common_head) {
    for (int num_contact = 0; num_contact < k_; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(common_head);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    EXPECT_EQ(((common_head + 1) * k_), GetContacts().size());
    EXPECT_EQ((common_head + 1), GetKBucketCount());
  }
}

TEST_P(RoutingTableSingleKTest, FUNC_AddContactPerformance1000RandomFill) {
  for (int num_contact = 0; num_contact < 1000; ++num_contact) {
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    AddContact(contact);

    size_t contacts_in_table(0);
    for (uint16_t i = 0; i < GetKBucketCount(); ++i) {
      size_t contacts_in_bucket = GetKBucketSizeForKey(i);
      ASSERT_GE(k_, contacts_in_bucket);
      contacts_in_table += contacts_in_bucket;
    }
    EXPECT_EQ(contacts_in_table, GetContacts().size());
  }
}

TEST_P(RoutingTableTest, BEH_GetCloseContacts) {
  NodeId target_id = GenerateUniqueRandomId(500);
  {
    // try to get close contacts from an empty routing table
    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_->GetCloseContacts(target_id, 1, exclude_contacts,
                                     close_contacts);
    EXPECT_EQ(0U, close_contacts.size());
  }
  {
    // try to get k close contacts from an k/2+1 filled routing table
    // with one un-validated contact
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_->AddContact(contact, rank_info_);
    EXPECT_EQ(k_ / 2, GetContacts().size());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_->GetCloseContacts(target_id, k_, exclude_contacts,
                                     close_contacts);
    EXPECT_EQ(k_ / 2, close_contacts.size());
  }
  Reset();
  {
    // try to get k close contacts from an k/2 filled routing table
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    EXPECT_EQ(k_ / 2, GetContacts().size());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_->GetCloseContacts(target_id, k_, exclude_contacts,
                                     close_contacts);
    EXPECT_EQ(k_ / 2, close_contacts.size());
  }
  Reset();
  {
    // try to get k close contacts from a k+1 filled routing table
    for (int num_contact = 0; num_contact < (k_ - 1); ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(500);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id_close = GenerateUniqueRandomId(500);
    Contact contact_close = ComposeContact(contact_id_close, 5000);
    AddContact(contact_close);
    NodeId contact_id_furthest = GenerateUniqueRandomId(501);
    Contact contact_furthest = ComposeContact(contact_id_furthest, 5000);
    AddContact(contact_furthest);
    EXPECT_EQ(k_ + 1, GetContacts().size());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_->GetCloseContacts(target_id, k_, exclude_contacts,
                                     close_contacts);
    EXPECT_EQ(k_, close_contacts.size());
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_close));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_furthest));
  }
  Reset();
  {
    // try to get k close contacts from a k+1 filled routing table,
    // with one defined exception contact
    for (int num_contact = 0; num_contact < (k_ - 2); ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(500);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id_close = GenerateUniqueRandomId(500);
    Contact contact_close = ComposeContact(contact_id_close, 5000);
    AddContact(contact_close);
    NodeId contact_id_exclude = GenerateUniqueRandomId(499);
    Contact contact_exclude = ComposeContact(contact_id_exclude, 5000);
    AddContact(contact_exclude);
    NodeId contact_id_furthest = GenerateUniqueRandomId(501);
    Contact contact_furthest = ComposeContact(contact_id_furthest, 5000);
    AddContact(contact_furthest);
    EXPECT_EQ(k_ + 1, GetContacts().size());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    exclude_contacts.push_back(contact_exclude);
    routing_table_->GetCloseContacts(target_id, k_, exclude_contacts,
                                     close_contacts);
    EXPECT_EQ(k_, close_contacts.size());
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_close));
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_furthest));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_exclude));
  }
  Reset();
  {
    // try to get k+21 close_contacts from a distributed filled routing_table
    // with one bucket contains k contacts having 111 common leading bits
    // and 16 buckets contains 2 contacts each, having 0-15 common leading bits

    // Initialize a routing table having the target to be the holder
    NodeId target_id = GenerateUniqueRandomId(505);
    std::vector<RoutingTableContact> target_routingtable;

    for (int num_contact = 0; num_contact < k_; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(400);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
      RoutingTableContact new_contact(contact, target_id, 0);
      target_routingtable.push_back(new_contact);
    }

    for (int common_head = 0; common_head < 16; ++common_head) {
      for (int num_contact = 0; num_contact < 2; ++num_contact) {
        NodeId contact_id = GenerateUniqueRandomId(common_head);
        Contact contact = ComposeContact(contact_id, 5000);
        AddContact(contact);
        RoutingTableContact new_contact(contact, target_id, 0);
        target_routingtable.push_back(new_contact);
      }
    }
    EXPECT_EQ(k_ + (16 * 2), GetContacts().size());
    EXPECT_EQ(17U, GetKBucketCount());
    EXPECT_EQ(k_ + (16 * 2), target_routingtable.size());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    // make sure the target_id in the exclude_contacts list
    exclude_contacts.push_back(ComposeContact(target_id, 5000));

    routing_table_->GetCloseContacts(target_id, k_ + 21, exclude_contacts,
                                     close_contacts);
    EXPECT_EQ(k_ + 21, close_contacts.size());

    std::sort(target_routingtable.begin(),
              target_routingtable.end(),
              [&](const RoutingTableContact &lhs,
                  const RoutingTableContact &rhs) {
      return NodeId::CloserToTarget(lhs.contact.node_id(),
                                    rhs.contact.node_id(),
                                    kHolderId());
    });
    uint32_t counter(0);
    auto it = target_routingtable.begin();
    while ((counter < (k_ + 21u)) && (it != target_routingtable.end())) {
      ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                                close_contacts.end(),
                                                (*it).contact));
      ++counter;
      ++it;
    }
  }
}

TEST_P(RoutingTableTest, BEH_UpdateRankInfo) {
  this->FillContactToRoutingTable();
  RankInfoPtr new_rank_info(new(transport::Info));
  new_rank_info->rtt = 13313;
  EXPECT_EQ(kFailedToFindContact,
            routing_table_->UpdateRankInfo(NodeId(NodeId::kRandomId),
                                          new_rank_info));
  ASSERT_EQ(0, routing_table_->UpdateRankInfo(contact_.node_id(),
                                             new_rank_info));
  auto all_contacts(GetContacts());
  auto itr(std::find_if(all_contacts.begin(),
                        all_contacts.end(),
                        [&](const RoutingTableContact &routing_table_contact) {
    return contact_.node_id() == routing_table_contact.contact.node_id();
  }));
  ASSERT_EQ(new_rank_info->rtt, (*itr).rank_info->rtt);

  Reset();
  {
    // try to update un-validated contact's rankinfo
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_->AddContact(contact, rank_info_);
    EXPECT_EQ(kFailedToFindContact,
              routing_table_->UpdateRankInfo(contact_id, new_rank_info));
  }
}

TEST_P(RoutingTableTest, BEH_IncrementFailedRpcCount) {
  this->FillContactToRoutingTable();
  EXPECT_EQ(kFailedToFindContact, routing_table_->IncrementFailedRpcCount(
      NodeId(NodeId::kRandomId)));
  auto all_contacts(GetContacts());
  auto itr(std::find_if(all_contacts.begin(),
                        all_contacts.end(),
                        [&](const RoutingTableContact &routing_table_contact) {
    return contact_.node_id() == routing_table_contact.contact.node_id();
  }));
  EXPECT_EQ(0, (*itr).num_failed_rpcs);
  ASSERT_EQ(kSuccess,
            routing_table_->IncrementFailedRpcCount(contact_.node_id()));
  all_contacts = GetContacts();
  itr = std::find_if(all_contacts.begin(),
                     all_contacts.end(),
                     [&](const RoutingTableContact &routing_table_contact) {
    return contact_.node_id() == routing_table_contact.contact.node_id();
  });
  ASSERT_EQ(1, (*itr).num_failed_rpcs);
  {
    // keep increasing one contact's failed RPC counter
    // till it gets removed
    size_t ori_size = GetContacts().size();
    uint16_t times_of_try = 0;
    do {
      ++times_of_try;
    } while ((routing_table_->IncrementFailedRpcCount(contact_.node_id()) ==
              kSuccess) && (times_of_try <= (kFailedRpcTolerance + 5)));
    // prevent deadlock
    if (times_of_try == (kFailedRpcTolerance + 5)) {
      FAIL();
    } else {
      ASSERT_EQ(ori_size-1, GetContacts().size());
    }
  }
  Reset();
  {
    // try to increase failed RPC counter of an un-validated contact
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_->AddContact(contact, rank_info_);
    EXPECT_EQ(kFailedToFindContact,
              routing_table_->IncrementFailedRpcCount(contact_id));
  }
}

TEST_P(RoutingTableTest, BEH_GetBootstrapContacts) {
  {
    this->FillContactToRoutingTable();
    std::vector<Contact> contacts;
    routing_table_->GetBootstrapContacts(&contacts);
    EXPECT_EQ(k_, contacts.size());
    EXPECT_EQ(contact_.node_id(),
        (std::find(contacts.begin(), contacts.end(), contact_))->node_id());
  }
  Reset();
  {
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_->AddContact(contact, rank_info_);
    std::vector<Contact> contacts;
    routing_table_->GetBootstrapContacts(&contacts);
    EXPECT_EQ(k_ / 2, contacts.size());
  }
}

TEST_P(RoutingTableTest, BEH_GetAllContacts) {
  {
    std::vector<Contact> contacts;
    routing_table_->GetAllContacts(&contacts);
    EXPECT_TRUE(contacts.empty());
  }
  {
    this->FillContactToRoutingTable();
    std::vector<Contact> contacts;
    routing_table_->GetAllContacts(&contacts);
    EXPECT_EQ(k_, contacts.size());
    EXPECT_EQ(contact_.node_id(),
        (std::find(contacts.begin(), contacts.end(), contact_))->node_id());
  }
}

TEST_P(RoutingTableTest, BEH_GetLocalRankInfo) {
  {
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    EXPECT_EQ(RankInfoPtr(), routing_table_->GetLocalRankInfo(contact));
  }
  {
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact);
    }
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    RankInfoPtr new_rank_info(new(transport::Info));
    new_rank_info->rtt = 13313;
    routing_table_->AddContact(contact, new_rank_info);
    routing_table_->SetValidated(contact.node_id(), true);
    EXPECT_EQ(new_rank_info->rtt,
              routing_table_->GetLocalRankInfo(contact)->rtt);
  }
}

TEST_P(RoutingTableSingleKTest, BEH_MutexTestWithMultipleThread) {
  const size_t kNumberOfThreads(10);
  const uint16_t kIteratorSize(10);
  std::vector<NodeId> node_ids_stored, node_ids_to_be_stored;
  std::vector<NodeId> node_ids_stored_then_deleted;
  std::vector<std::pair<RankInfoPtr, IP>> stored_attrs;
  std::set <NodeId> unique_node_ids;
  bool unique(false);
  for (uint16_t i = 0; i < kIteratorSize; ++i) {
    // Node ids stored
    {
      NodeId node_id;
      do {
        auto it = unique_node_ids.insert(GenerateUniqueRandomId(i + 1));
        unique = it.second;
        if (unique)
          node_id = *(it.first);
      } while (!unique);
      Contact contact = ComposeContact(node_id, 5001 + i);
      AddContact(contact);
      node_ids_stored.push_back(node_id);
    }
    // Node ids to be stored
    {
      NodeId node_id;
      do {
        auto it = unique_node_ids.insert(GenerateUniqueRandomId(i + 1));
        unique = it.second;
        if (unique)
          node_id = (*it.first);
      } while (!unique);
      Contact contact = ComposeContact(node_id, 5001 + (i + kIteratorSize));
      node_ids_to_be_stored.push_back(node_id);
    }
    // Node ids stored then deleted
    {
      NodeId node_id;
      do {
        auto it = unique_node_ids.insert(
                      GenerateUniqueRandomId(i + kIteratorSize + 1));
        unique = it.second;
        if (unique)
          node_id = (*it.first);
      } while (!unique);
      Contact contact = ComposeContact(node_id,
                                       5001 + (i + 2 * kIteratorSize));
      node_ids_stored_then_deleted.push_back(node_id);
    }
    // Constructing attributes vector
    RankInfoPtr new_rank_info(new(transport::Info));
    new_rank_info->rtt = 13313 + i;
    IP ip = IP::from_string("127.0.0.1");
    stored_attrs.push_back(std::make_pair(new_rank_info, ip));
  }
  EXPECT_EQ(node_ids_stored.size(), GetContacts().size());
  // Posting all the jobs
  AsioService asio_service;
  for (uint16_t i = 0; i < kIteratorSize; ++i) {
    Contact contact = ComposeContact(node_ids_to_be_stored[i], 6001 + i);
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoAddContact, this, contact));
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoGetCloseContacts, this, 10));
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoUpdateRankInfo, this,
                  node_ids_stored[i], stored_attrs[i].first));
    // Add and then remove contacts using IncrementFailedRpcCount()
    Contact contact_1 = ComposeContact(node_ids_stored_then_deleted[i],
                                       7001 + i);
    asio_service.service().post(
        std::bind(&RoutingTableSingleKTest::DoAddRemoveContact, this,
                  contact_1));
  }
  // Running the threads
  asio_service.Start(kNumberOfThreads);
  node_ids_stored.insert(node_ids_stored.end(), node_ids_to_be_stored.begin(),
                         node_ids_to_be_stored.end());
  int count(0), attempts(1000);
  while ((node_ids_stored.size() != GetContacts().size()) &&
         (count++ != attempts)) {
    Sleep(boost::posix_time::milliseconds(1));
  }
  asio_service.Stop();
  // Verifying results
  ASSERT_EQ(node_ids_stored.size(), GetContacts().size());
  for (uint16_t i = 0; i < node_ids_stored.size(); ++i) {
    Contact result;
    GetContact(node_ids_stored[i], &result);
    EXPECT_EQ(node_ids_stored[i], result.node_id());
  }
  // Checking changed attributes
  auto all_contacts(GetContacts());
  for (int i = 0; i < kIteratorSize; ++i) {
    auto itr(std::find_if(all_contacts.begin(),
                          all_contacts.end(),
                         [&](const RoutingTableContact &routing_table_contact) {
      return node_ids_stored[i] == routing_table_contact.contact.node_id();
    }));
    EXPECT_EQ(stored_attrs[i].first->rtt, (*itr).rank_info->rtt);
    EXPECT_EQ(stored_attrs[i].second, (*itr).contact.PreferredEndpoint().ip);
  }
}

}  // namespace test

}  // namespace dht

}  // namespace maidsafe
