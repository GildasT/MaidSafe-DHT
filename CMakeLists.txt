#==============================================================================#
#                                                                              #
#  Copyright (c) 2011 MaidSafe.net limited                                     #
#  All rights reserved.                                                        #
#                                                                              #
#  Redistribution and use in source and binary forms, with or without          #
#  modification, are permitted provided that the following conditions are met: #
#                                                                              #
#      * Redistributions of source code must retain the above copyright        #
#        notice, this list of conditions and the following disclaimer.         #
#      * Redistributions in binary form must reproduce the above copyright     #
#        notice, this list of conditions and the following disclaimer in the   #
#        documentation and/or other materials provided with the distribution.  #
#      * Neither the name of the maidsafe.net limited nor the names of its     #
#        contributors may be used to endorse or promote products derived from  #
#        this software without specific prior written permission.              #
#                                                                              #
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" #
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  #
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE  #
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR         #
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF        #
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    #
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN     #
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)     #
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  #
#  POSSIBILITY OF SUCH DAMAGE.                                                 #
#                                                                              #
#==============================================================================#
#                                                                              #
#  Written by maidsafe.net team                                                #
#                                                                              #
#==============================================================================#

set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
SET(MS_PROJECT_NAME dht)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.4 FATAL_ERROR)
MESSAGE("================================================================================\n")
project(dht)
set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/dht/*.proto")
include(../../cmake_modules/maidsafe_standard_setup.cmake)
include_directories(${common_SOURCE_DIR}/include)
include_directories(${transport_SOURCE_DIR}/include)

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
FILE(GLOB SOURCE_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.cc")
FILE(GLOB HEADER_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.h")
FILE(GLOB PROTO_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.proto")
#FILE(GLOB SOURCE_PROTO_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.pb.cc")
#FILE(GLOB HEADER_PROTO_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.pb.h")
SET(ALL_FILES_DHT_DIR ${SOURCE_FILES_DHT_DIR} ${HEADER_FILES_DHT_DIR} ${PROTO_FILES_DHT_DIR})
SET(STYLE_DHT ${ALL_FILES_DHT_DIR})
#LIST(REMOVE_ITEM STYLE_DHT ${SOURCE_PROTO_FILES_DHT_DIR} ${HEADER_PROTO_FILES_DHT_DIR} ${PROTO_FILES_DHT_DIR})
#LIST(REMOVE_ITEM SOURCE_FILES_DHT_DIR ${SOURCE_PROTO_FILES_DHT_DIR})
#LIST(REMOVE_ITEM HEADER_FILES_DHT_DIR ${HEADER_PROTO_FILES_DHT_DIR})
SOURCE_GROUP("DHT Source Files" FILES ${SOURCE_FILES_DHT_DIR})
SOURCE_GROUP("DHT Header Files" FILES ${HEADER_FILES_DHT_DIR})
#SOURCE_GROUP("DHT Proto Files" FILES ${PROTO_FILES_DHT_DIR} ${SOURCE_PROTO_FILES_DHT_DIR} ${HEADER_PROTO_FILES_DHT_DIR})

####    BENCHMARK, DEMO & TESTS    ####
FILE(GLOB SOURCE_FILES_BENCHMARK_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/benchmark/*.cc")
FILE(GLOB HEADER_FILES_BENCHMARK_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/benchmark/*.h")
SET(ALL_FILES_BENCHMARK_DIR ${SOURCE_FILES_BENCHMARK_DIR} ${HEADER_FILES_BENCHMARK_DIR})
SOURCE_GROUP("Benchmark Source Files" FILES ${SOURCE_FILES_BENCHMARK_DIR})
SOURCE_GROUP("Benchmark Header Files" FILES ${HEADER_FILES_BENCHMARK_DIR})

FILE(GLOB SOURCE_FILES_DEMO_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/demo/*.cc")
FILE(GLOB HEADER_FILES_DEMO_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/demo/*.h")
SET(ALL_FILES_DEMO_DIR ${SOURCE_FILES_DEMO_DIR} ${HEADER_FILES_DEMO_DIR})
SOURCE_GROUP("Demo Source Files" FILES ${SOURCE_FILES_DEMO_DIR})
SOURCE_GROUP("Demo Header Files" FILES ${HEADER_FILES_DEMO_DIR})

FILE(GLOB SOURCE_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.cc")
FILE(GLOB HEADER_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.h")
FILE(GLOB PROTO_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.proto")
FILE(GLOB SOURCE_PROTO_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.pb.cc")
FILE(GLOB HEADER_PROTO_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.pb.h")
SET(ALL_FILES_DHT_TESTS_DIR ${SOURCE_FILES_DHT_TESTS_DIR} ${HEADER_FILES_DHT_TESTS_DIR} ${PROTO_FILES_DHT_TESTS_DIR})
SET(STYLE_DHT_TESTS ${ALL_FILES_DHT_TESTS_DIR})
LIST(REMOVE_ITEM STYLE_DHT_TESTS ${SOURCE_PROTO_FILES_DHT_TESTS_DIR} ${HEADER_PROTO_FILES_DHT_TESTS_DIR} ${PROTO_FILES_DHT_TESTS_DIR})
#LIST(REMOVE_ITEM SOURCE_FILES_DHT_TESTS_DIR ${SOURCE_PROTO_FILES_DHT_TESTS_DIR})
#LIST(REMOVE_ITEM HEADER_FILES_DHT_TESTS_DIR ${HEADER_PROTO_FILES_DHT_TESTS_DIR})
SOURCE_GROUP("DHT Tests Source Files" FILES ${SOURCE_FILES_DHT_TESTS_DIR})
SOURCE_GROUP("DHT Tests Header Files" FILES ${HEADER_FILES_DHT_TESTS_DIR})
SOURCE_GROUP("DHT Tests Proto Files" FILES ${PROTO_FILES_DHT_TESTS_DIR} ${SOURCE_PROTO_FILES_DHT_TESTS_DIR} ${HEADER_PROTO_FILES_DHT_TESTS_DIR})

FILE(GLOB SOURCE_FILES_DHT_TESTS_FUNCTIONAL_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/*.cc")
FILE(GLOB HEADER_FILES_DHT_TESTS_FUNCTIONAL_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/*.h")
SET(ALL_FILES_DHT_TESTS_FUNCTIONAL_DIR ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_DIR} ${HEADER_FILES_DHT_TESTS_FUNCTIONAL_DIR})
SOURCE_GROUP("Functional Tests Source Files" FILES ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_DIR})
SOURCE_GROUP("Functional Tests Header Files" FILES ${HEADER_FILES_DHT_TESTS_FUNCTIONAL_DIR})

SET(SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/node_test.cc"
                                           "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/test_utils.cc"
                                           "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/test_main.cc")
set(SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE_IMPL "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/node_impl_test.cc"
                                                "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/test_utils.cc"
                                                "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/test_main.cc")
set(SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE_CHURN "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/node_churn_test.cc"
                                                 "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/test_utils.cc"
                                                 "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/test_main.cc")
set(HEADER_FILES_DHT_TESTS_FUNCTIONALS "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/test_node_environment.h"
                                       "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/test_utils.h"
                                       "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/local_network.h")


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(${MS_PROJECT_NAME} ${ALL_FILES_DHT_DIR})
ms_add_executable(TESTkademlia Tests ${ALL_FILES_DHT_TESTS_DIR})
ms_add_executable(TESTnode_functional Tests ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE} ${HEADER_FILES_DHT_TESTS_FUNCTIONALS})
ms_add_executable(TESTnode_impl_functional Tests ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE_IMPL} ${HEADER_FILES_DHT_TESTS_FUNCTIONALS})
ms_add_executable(TESTnode_churn Tests ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE_CHURN} ${HEADER_FILES_DHT_TESTS_FUNCTIONALS})
ms_add_executable(KademliaDemo Demo ${ALL_FILES_DEMO_DIR})
ms_add_executable(Benchmark Benchmark ${ALL_FILES_BENCHMARK_DIR})

# This target allows maidsafe_dht_static to be installed without building all project targets
IF(MSVC)
  ADD_CUSTOM_TARGET(install_fast ${CMAKE_COMMAND} -DBUILD_TYPE=$<CONFIGURATION> -P ${CMAKE_BINARY_DIR}/cmake_install.cmake)
ELSE()
  ADD_CUSTOM_TARGET(install_fast ${CMAKE_COMMAND} -DBUILD_TYPE=${CMAKE_BUILD_TYPE} -P ${CMAKE_BINARY_DIR}/cmake_install.cmake)
ENDIF()
ADD_DEPENDENCIES(install_fast maidsafe_dht)

IF(NOT APPLE)
TARGET_LINK_LIBRARIES(maidsafe_dht
                        maidsafe_transport
                        maidsafe_common
                      #  breakpad_static
                        boost_date_time_static
                        boost_regex_static)
ELSE()
TARGET_LINK_LIBRARIES(maidsafe_dht
                        maidsafe_transport
                        maidsafe_common
                        boost_date_time_static
                        boost_regex_static)
ENDIF()
TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_dht)
TARGET_LINK_LIBRARIES(TESTnode_functional maidsafe_dht)
TARGET_LINK_LIBRARIES(TESTnode_impl_functional maidsafe_dht)
TARGET_LINK_LIBRARIES(TESTnode_churn maidsafe_dht)
TARGET_LINK_LIBRARIES(KademliaDemo maidsafe_dht boost_program_options_static)
TARGET_LINK_LIBRARIES(Benchmark maidsafe_dht boost_program_options_static)


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)

set_target_properties(TESTnode_functional PROPERTIES COMPILE_DEFINITIONS "FUNCTIONAL_NODE_TEST")
set_target_properties(TESTnode_impl_functional PROPERTIES COMPILE_DEFINITIONS "FUNCTIONAL_NODE_IMPL_TEST")
set_target_properties(TESTnode_churn PROPERTIES COMPILE_DEFINITIONS "FUNCTIONAL_CHURN_TEST")

if(MSVC)
  # Warnings switched off for protocol buffer generated files
  set_source_files_properties(${PROJECT_SOURCE_DIR}/src/maidsafe/dht/kademlia.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/rpcs.pb.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/wrapper.pb.cc
                                PROPERTIES COMPILE_FLAGS "/W0")
  SET_TARGET_PROPERTIES(maidsafe_dht TESTkademlia PROPERTIES COMPILE_FLAGS "/bigobj")
ELSEIF(UNIX)
  SET_TARGET_PROPERTIES(KademliaDemo PROPERTIES COMPILE_FLAGS "-g")
  FILE(GLOB PROTO_SOURCE_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.pb.cc"
                               "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.pb.cc")
  set_source_files_properties(${PROJECT_SOURCE_DIR}/src/maidsafe/dht/service.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/node.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/node_impl.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/benchmark/benchmark.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/test_main.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/mock_rpcs_test.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/mock_node_impl_test.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/rpcs_test.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/services_test.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/node_churn_test
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/node_test.cc
                              ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/node_impl_test.cc
                              PROPERTIES COMPILE_FLAGS "-Wno-effc++")
  set_source_files_properties(${PROTO_SOURCE_FILES} PROPERTIES COMPILE_FLAGS "-w")
endif()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
add_style_test(${STYLE_DHT}
               ${ALL_FILES_BENCHMARK_DIR}
               ${ALL_FILES_DEMO_DIR}
               ${STYLE_DHT_TESTS}
               ${ALL_FILES_DHT_TESTS_FUNCTIONAL_DIR})

add_gtests(TESTkademlia)
add_gtests(TESTnode_functional)
add_gtests(TESTnode_impl_functional)
add_gtests(TESTnode_churn)

test_summary_output()

# Remove most lengthy tests and style checkers from MemCheck runs.
add_memcheck_ignore(STYLE_CHECK)
add_memcheck_ignore(NodeTest.FUNC_Ping)
add_memcheck_ignore(NodeTest.FUNC_Bootstrap)
add_memcheck_ignore(NodeTest.FUNC_JoinClient)
add_memcheck_ignore(NodeTest.FUNC_StoreAndFindSmallValue)
add_memcheck_ignore(NodeTest.FUNC_StoreAndFindBigValue)
add_memcheck_ignore(NodeTest.FUNC_StoreAndFindMultipleValues)
add_memcheck_ignore(NodeTest.FUNC_MultipleNodesFindSingleValue)
add_memcheck_ignore(NodeTest.FUNC_ClientFindValue)
add_memcheck_ignore(NodeTest.FUNC_GetContact)
add_memcheck_ignore(NodeTest.FUNC_FindNonExistingValue)
add_memcheck_ignore(NodeTest.FUNC_FindDeadNode)
add_memcheck_ignore(NodeTest.FUNC_JoinLeave)
add_memcheck_ignore(NodeTest.FUNC_StoreWithInvalidRequest)
add_memcheck_ignore(NodeTest.FUNC_Update)
add_memcheck_ignore(NodeTest.FUNC_FindNodes)
add_memcheck_ignore(NodeTest.FUNC_Delete)
add_memcheck_ignore(NodeTest.FUNC_InvalidDeleteRequest)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_JoinLeave/0)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_JoinLeave/1)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_FindNodes/0)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_FindNodes/1)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_Store/0)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_Store/1)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_FindValue/0)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_FindValue/1)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_Delete/0)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_Delete/1)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_Update/1)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_StoreRefresh/0)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_StoreRefresh/1)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_DeleteRefresh/0)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_DeleteRefresh/1)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_GetContact/0)
add_memcheck_ignore(FullOrClient/NodeImplTest.FUNC_GetContact/1)
add_memcheck_ignore(NodeChurnTest.FUNC_RandomStartStopNodes)


# ###################################################################################################
# # Install details                                                                                 #
# ###################################################################################################
# FINAL_MESSAGE()
# RENAME_OUTDATED_BUILT_EXES()
# 
# SET(MAIDSAFE_DHT_INSTALL_FILES
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/config.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/contact.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/maidsafe-dht.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/message_handler.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/node-api.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/node_container.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/node_id.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/return_codes.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/rpcs_objects.h
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/version.h)
# 
# SET(MAIDSAFE_DHT_TEST_INSTALL_FILES
#       ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/local_network.h)
# 
# MS_INSTALL_LIBS(maidsafe_dht_static)
# MS_INSTALL_HEADERS(dht ${MAIDSAFE_DHT_INSTALL_FILES})
# MS_INSTALL_HEADERS(dht/tests ${MAIDSAFE_DHT_TEST_INSTALL_FILES})
# MS_INSTALL_EXPORT()
