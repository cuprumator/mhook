cmake_minimum_required(VERSION 2.8)
project(mhook)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
add_definitions(-DUNICODE -D_UNICODE)

set(COMPILER_DEPENDENT_LIBS "")
if(NOT MSVC)
	# Suppress warnings.
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pointer-to-int-cast")
	set(COMPILER_DEPENDENT_LIBS ws2_32)
endif()

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

add_subdirectory("${CMAKE_SOURCE_DIR}/3rd-party/gtest/googletest")

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
include_directories("${CMAKE_SOURCE_DIR}")

file(GLOB DisasmCxx disasm-lib/*.cpp disasm-lib/*.c)
file(GLOB DisasmH disasm-lib/*.h)
set(DisasmSrc ${DisasmCxx} ${DisasmH})

file(GLOB MhookCxx mhook-lib/*.cpp mhook-lib/*.c)
file(GLOB MhookH mhook-lib/*.h)
set(MhookSrc ${MhookCxx} ${MhookH})

source_group("Source Files\\disasm-lib" FILES ${DisasmCxx})
source_group("Header Files\\disasm-lib" FILES ${DisasmH})

# Static lib for linking
add_library(mhook STATIC ${DisasmSrc} ${MhookSrc})

# Tests
# Original tests
file(GLOB OrigTestSrc tests/legacy-tests/*.cpp tests/legacy-tests/*.h)
add_executable(mhook-legacy-tests ${OrigTestSrc})
set_target_properties(mhook-legacy-tests PROPERTIES FOLDER tests)
target_link_libraries(mhook-legacy-tests mhook ${COMPILER_DEPENDENT_LIBS})
# Unit Tests
file(GLOB UnitTestSrc tests/unit-tests/*.cpp tests/unit-test/*.h)
add_executable(mhook-unit-tests ${UnitTestSrc})
set_target_properties(mhook-unit-tests PROPERTIES FOLDER tests)
set_target_properties(gtest PROPERTIES FOLDER tests/gtest)
set_target_properties(gtest_main PROPERTIES FOLDER tests/gtest)
target_link_libraries(mhook-unit-tests mhook gtest gtest_main ${COMPILER_DEPENDENT_LIBS})