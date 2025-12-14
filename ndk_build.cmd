@echo off

set NDK=D:\androidsdk\ndk\29.0.14206865
set CMK=D:\androidsdk\cmake\4.1.2
@REM 24 is needed for libuv
set MINSDKVER=24

for %%I in (arm64-v8a armeabi-v7a x86_64 x86) do (
    echo Building Trp for %%I...

    mkdir build_ndk\%%I
    %CMK%\bin\cmake -DCMAKE_TOOLCHAIN_FILE=%NDK%\build\cmake\android.toolchain.cmake -DANDROID_ABI=%%I ^
        -DANDROID_NATIVE_API_LEVEL=%MINSDKVER% -DCMAKE_MAKE_PROGRAM=%CMK%\bin\ninja ^
        -DCMAKE_BUILD_TYPE=MinSizeRel -DDISABLE_LOG=ON -G Ninja -B build_ndk\%%I
    %CMK%\bin\cmake --build build_ndk\%%I --config MinSizeRel

    if not exist build_ndk\%%I\trp-socks (
        echo Build Trp for %%I failed
        pause
        exit /b 1
    )
    mkdir build_ndk\release\%%I
    %NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe -o build_ndk\release\%%I\libsslocal.so build_ndk\%%I\trp-socks
)
