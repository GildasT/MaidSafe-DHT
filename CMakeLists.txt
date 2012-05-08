#==============================================================================#
#                                                                              #
#  Copyright (c) 2012 MaidSafe.net limited                                     #
#                                                                              #
#  The following source code is property of MaidSafe.net limited and is not    #
#  meant for external use.  The use of this code is governed by the license    #
#  file licence.txt found in the root directory of this project and also on    #
#  www.maidsafe.net.                                                           #
#                                                                              #
#  You are not free to copy, amend or otherwise use this source code without   #
#  the explicit written permission of the board of directors of MaidSafe.net.  #
#                                                                              #
#==============================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)
project(dht)

set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB PROTO_FILES_KADEMLIA RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/dht/*.proto")
file(GLOB PROTO_FILES_TESTS RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/dht/tests/*.proto")
set(PROTO_FILES "${PROTO_FILES_KADEMLIA};${PROTO_FILES_TESTS}")
include(../../cmake_modules/maidsafe_standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${transport_SOURCE_DIR}/include)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
file(GLOB SOURCE_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.cc")
file(GLOB HEADER_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.h")
file(GLOB PROTO_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.proto")
file(GLOB SOURCE_PROTO_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.pb.cc")
file(GLOB HEADER_PROTO_FILES_DHT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/*.pb.h")
set(ALL_FILES_DHT_DIR ${SOURCE_FILES_DHT_DIR} ${HEADER_FILES_DHT_DIR} ${PROTO_FILES_DHT_DIR})
set(STYLE_DHT ${ALL_FILES_DHT_DIR})
list(REMOVE_ITEM STYLE_DHT ${SOURCE_PROTO_FILES_DHT_DIR} ${HEADER_PROTO_FILES_DHT_DIR} ${PROTO_FILES_DHT_DIR})
list(REMOVE_ITEM SOURCE_FILES_DHT_DIR ${SOURCE_PROTO_FILES_DHT_DIR})
list(REMOVE_ITEM HEADER_FILES_DHT_DIR ${HEADER_PROTO_FILES_DHT_DIR})
source_group("DHT Source Files" FILES ${SOURCE_FILES_DHT_DIR})
source_group("DHT Header Files" FILES ${HEADER_FILES_DHT_DIR})
source_group("DHT Proto Files" FILES ${PROTO_FILES_DHT_DIR} ${SOURCE_PROTO_FILES_DHT_DIR} ${HEADER_PROTO_FILES_DHT_DIR})

####    BENCHMARK, DEMO & TESTS    ####
file(GLOB SOURCE_FILES_BENCHMARK_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/benchmark/*.cc")
file(GLOB HEADER_FILES_BENCHMARK_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/benchmark/*.h")
set(ALL_FILES_BENCHMARK_DIR ${SOURCE_FILES_BENCHMARK_DIR} ${HEADER_FILES_BENCHMARK_DIR})
source_group("Benchmark Source Files" FILES ${SOURCE_FILES_BENCHMARK_DIR})
source_group("Benchmark Header Files" FILES ${HEADER_FILES_BENCHMARK_DIR})

file(GLOB SOURCE_FILES_DEMO_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/demo/*.cc")
file(GLOB HEADER_FILES_DEMO_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/demo/*.h")
set(ALL_FILES_DEMO_DIR ${SOURCE_FILES_DEMO_DIR} ${HEADER_FILES_DEMO_DIR})
source_group("Demo Source Files" FILES ${SOURCE_FILES_DEMO_DIR})
source_group("Demo Header Files" FILES ${HEADER_FILES_DEMO_DIR})

file(GLOB SOURCE_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.cc")
file(GLOB HEADER_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.h")
file(GLOB PROTO_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.proto")
file(GLOB SOURCE_PROTO_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.pb.cc")
file(GLOB HEADER_PROTO_FILES_DHT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/*.pb.h")
set(ALL_FILES_DHT_TESTS_DIR ${SOURCE_FILES_DHT_TESTS_DIR} ${HEADER_FILES_DHT_TESTS_DIR} ${PROTO_FILES_DHT_TESTS_DIR})
set(STYLE_DHT_TESTS ${ALL_FILES_DHT_TESTS_DIR})
list(REMOVE_ITEM STYLE_DHT_TESTS ${SOURCE_PROTO_FILES_DHT_TESTS_DIR} ${HEADER_PROTO_FILES_DHT_TESTS_DIR} ${PROTO_FILES_DHT_TESTS_DIR})
list(REMOVE_ITEM SOURCE_FILES_DHT_TESTS_DIR ${SOURCE_PROTO_FILES_DHT_TESTS_DIR})
list(REMOVE_ITEM HEADER_FILES_DHT_TESTS_DIR ${HEADER_PROTO_FILES_DHT_TESTS_DIR})
source_group("DHT Tests Source Files" FILES ${SOURCE_FILES_DHT_TESTS_DIR})
source_group("DHT Tests Header Files" FILES ${HEADER_FILES_DHT_TESTS_DIR})
source_group("DHT Tests Proto Files" FILES ${PROTO_FILES_DHT_TESTS_DIR} ${SOURCE_PROTO_FILES_DHT_TESTS_DIR} ${HEADER_PROTO_FILES_DHT_TESTS_DIR})

file(GLOB SOURCE_FILES_DHT_TESTS_FUNCTIONAL_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/*.cc")
file(GLOB HEADER_FILES_DHT_TESTS_FUNCTIONAL_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/*.h")
set(ALL_FILES_DHT_TESTS_FUNCTIONAL_DIR ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_DIR} ${HEADER_FILES_DHT_TESTS_FUNCTIONAL_DIR})
source_group("Functional Tests Source Files" FILES ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_DIR})
source_group("Functional Tests Header Files" FILES ${HEADER_FILES_DHT_TESTS_FUNCTIONAL_DIR})

set(SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE "${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/functional/node_test.cc"
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
ms_add_static_library(dht ${ALL_FILES_DHT_DIR})
ms_add_executable(TESTkademlia "Tests/DHT" ${ALL_FILES_DHT_TESTS_DIR})
ms_add_executable(TESTnode_functional "Tests/DHT" ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE} ${HEADER_FILES_DHT_TESTS_FUNCTIONALS})
ms_add_executable(TESTnode_impl_functional "Tests/DHT" ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE_IMPL} ${HEADER_FILES_DHT_TESTS_FUNCTIONALS})
ms_add_executable(TESTnode_churn "Tests/DHT" ${SOURCE_FILES_DHT_TESTS_FUNCTIONAL_NODE_CHURN} ${HEADER_FILES_DHT_TESTS_FUNCTIONALS})
ms_add_executable(KademliaDemo Demos ${ALL_FILES_DEMO_DIR})
ms_add_executable(KademliaBenchmark Benchmarks ${ALL_FILES_BENCHMARK_DIR})

# This target allows maidsafe_dht to be installed without building all project targets
if(MSVC)
  add_custom_target(install_dht_fast ${CMAKE_COMMAND} -DBUILD_TYPE=$<CONFIGURATION> -P ${CMAKE_BINARY_DIR}/cmake_install.cmake)
else()
  add_custom_target(install_dht_fast ${CMAKE_COMMAND} -DBUILD_TYPE=${CMAKE_BUILD_TYPE} -P ${CMAKE_BINARY_DIR}/cmake_install.cmake)
endif()
add_dependencies(install_dht_fast maidsafe_dht)
set_target_properties(install_dht_fast PROPERTIES FOLDER "MaidSafe")


target_link_libraries(maidsafe_dht maidsafe_transport)
target_link_libraries(TESTkademlia maidsafe_dht)
target_link_libraries(TESTnode_functional maidsafe_dht)
target_link_libraries(TESTnode_impl_functional maidsafe_dht)
target_link_libraries(TESTnode_churn maidsafe_dht)
target_link_libraries(KademliaDemo maidsafe_dht boost_program_options-static)
target_link_libraries(KademliaBenchmark maidsafe_dht boost_program_options-static)
rename_outdated_built_exes()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)

set_target_properties(TESTnode_functional PROPERTIES COMPILE_DEFINITIONS "FUNCTIONAL_NODE_TEST")
set_target_properties(TESTnode_impl_functional PROPERTIES COMPILE_DEFINITIONS "FUNCTIONAL_NODE_IMPL_TEST")
set_target_properties(TESTnode_churn PROPERTIES COMPILE_DEFINITIONS "FUNCTIONAL_CHURN_TEST")

ms_disable_warnings(${PROJECT_SOURCE_DIR}/src/maidsafe/dht/kademlia.pb.cc
                    ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/rpcs.pb.cc
                    ${PROJECT_SOURCE_DIR}/src/maidsafe/dht/tests/wrapper.pb.cc)

if(MSVC)
  set_target_properties(maidsafe_dht TESTkademlia PROPERTIES COMPILE_FLAGS "/bigobj")
elseif(UNIX)
  set_target_properties(KademliaDemo PROPERTIES COMPILE_FLAGS "-g")
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
