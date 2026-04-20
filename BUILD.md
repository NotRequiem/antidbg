# Building process

## Visual Studio (recommended for MSVC)

Click on the .sln file, select "Release" and click on "Build" to generate a test program

For **building**, cd to the project root and:
mkdir build \&\& cd build

cmake .. -A x64

cmake --build . --config Release



## MinGW-w64 (GCC)

Ensure you launch the 64-bit MinGW environment (this assumes gcc is in your PATH) and run:
mkdir build \&\& cd build

cmake .. -G "MinGW Makefiles"

cmake --build .



## Clang

Using Ninja as generator:

mkdir build \&\& cd build

cmake .. -G Ninja -DCMAKE\_C\_COMPILER=clang

cmake --build .



