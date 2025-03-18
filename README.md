TODO: bring the entire blender repo in here so we can just clone & build

Just place the fuzz_harness folder in blender/source/blender/. Change the blender/source/blender/CMakeLists.txt and add add_subdirectory(fuzz_harness). Run export CC=afl-clang-fast and CXX=afl-clang-fast++ and run make in /blender and it should build just fine. fuzz_harness will be in blender/bin, ready for afl-fuzz.
