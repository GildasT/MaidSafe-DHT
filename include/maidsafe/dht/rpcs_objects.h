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

#ifndef MAIDSAFE_DHT_RPCS_OBJECTS_H_
#define MAIDSAFE_DHT_RPCS_OBJECTS_H_

#include <map>
#include <string>
#include <utility>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/transport/transport.h"

#include "maidsafe/dht/config.h"


namespace maidsafe  {

namespace dht {

/* This class temporarily holds the connected objects of RPCs to ensure all
 * resources can be correctly released and no memory leaked.
 */
class ConnectedObjectsList  {
 public:
  typedef std::map<uint32_t, std::pair<TransportPtr, MessageHandlerPtr>>
      ObjectsContainer;

  ConnectedObjectsList();
  ~ConnectedObjectsList();

  // Adds connected objects to the container and returns their index.
  uint32_t AddObject(const TransportPtr transport,
                     const MessageHandlerPtr message_handler);

  // Tries to remove existing entry based on index, returns whether successful.
  bool RemoveObject(uint32_t index);

  // Sends message if concurrent RPCs below limit, otherwise calls OnError.
  static void TryToSend(boost::asio::io_service &asio_service,  // NOLINT
                        const TransportPtr transport,
                        const std::string &data,
                        const transport::Endpoint &endpoint,
                        const transport::Timeout &timeout);

  // Returns an existing transport entry based on index.
  TransportPtr GetTransport(uint32_t index);

  // Returns the number of connected objects entries.
  size_t Size();

 private:
  ConnectedObjectsList(const ConnectedObjectsList&);
  ConnectedObjectsList& operator=(const ConnectedObjectsList&);

  ObjectsContainer objects_container_;
  static boost::mutex mutex_;
  static boost::condition_variable cond_var_;
  uint32_t index_;
  static size_t total_count_;
};

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_RPCS_OBJECTS_H_
