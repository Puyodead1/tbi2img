cmake_minimum_required(VERSION 3.16)
project(tbi2img LANGUAGES CXX)
add_executable(tbi2img tbi2img.cpp)
target_compile_features(tbi2img PRIVATE cxx_std_17)
if(MSVC)
  target_compile_options(tbi2img PRIVATE /W4 /permissive-)
  # This program has no runtime DLL dependencies. Disable vcpkg's applocal
  # post-build script so builds do not require PowerShell 7 (pwsh.exe).
  set_property(TARGET tbi2img PROPERTY VCPKG_APPLOCAL_DEPS OFF)
else()
  target_compile_options(tbi2img PRIVATE -Wall -Wextra -Wpedantic)
endif()
