# Building process
## Visual Studio (recommended for MSVC)

Click on the .sln file, select "Release" and click on "Build" to generate a test program

For **building**, cd to the project root and:
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release


## MinGW-w64 (GCC)
Ensure you launch the 64-bit MinGW environment and run:
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build --config Release


## Ninja with Clang/GCC
ensure your toolchain is 64-bit and run:
cmake -S . -B build -G Ninja
cmake --build build --config Release

# Notes
CMake can’t force the toolchain to be 64-bit, you must invoke CMake with a 64-bit generator or toolchain (Visual Studio -A x64, a 64-bit MinGW-w64, or a 64-bit clang/gcc). The CMake script will abort if the configured target is not 64-bit.

