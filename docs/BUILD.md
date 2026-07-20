# Build Instructions

## Prerequisites

### System Requirements
- Linux kernel 5.1 or later (for io-uring support)
- x86_64 or ARM64 architecture
- Root or CAP_NET_ADMIN capability (for TUN device creation)

### Required Packages

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    liburing-dev \
    libssl-dev \
    pkg-config
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install -y \
    gcc \
    cmake \
    liburing-devel \
    openssl-devel \
    pkgconfig
```

**Arch Linux:**
```bash
sudo pacman -S \
    base-devel \
    cmake \
    liburing \
    openssl \
    pkgconfig
```

## Building

### 1. Clone the Repository
```bash
git clone <repository-url>
cd dataplane
```

### 2. Generate Test Certificates
```bash
cd certs
./generate_certs.sh
cd ..
```

This creates:
- `server_cert.pem` and `server_key.pem` for the server
- `client_cert.pem` and `client_key.pem` for the client (optional)

### 3. Build with CMake

**Debug Build:**
```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

**Release Build:**
```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 4. Verify Build
```bash
ls -lh vpn_server vpn_client example_server example_client
```

You should see four executables.

## Build Options

### Custom OpenSSL Location
```bash
cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl ..
```

### Custom liburing Location
```bash
cmake -DLIBURING_ROOT=/usr/local ..
```

### Verbose Build
```bash
make VERBOSE=1
```

## Installation

### System-wide Installation
```bash
sudo make install
```

This installs:
- Executables to `/usr/local/bin/`
- Library to `/usr/local/lib/`
- Headers to `/usr/local/include/dtls_vpn/`

### Custom Installation Prefix
```bash
cmake -DCMAKE_INSTALL_PREFIX=/opt/dtls-vpn ..
make
sudo make install
```

## Setting Capabilities

Instead of running as root, set capabilities:

```bash
# For server
sudo setcap cap_net_admin+ep build/vpn_server

# For client
sudo setcap cap_net_admin+ep build/vpn_client
```

Now you can run without sudo:
```bash
./build/vpn_server 4433 certs/server_cert.pem certs/server_key.pem
./build/vpn_client 127.0.0.1 4433
```

## Troubleshooting

### "liburing not found"
```bash
# Check if liburing is installed
pkg-config --modversion liburing

# If not found, install it
sudo apt-get install liburing-dev  # Ubuntu/Debian
```

### "OpenSSL not found"
```bash
# Check OpenSSL version
openssl version

# Should be 1.1.1 or later
# If not, install/upgrade
sudo apt-get install libssl-dev
```

### "io_uring_queue_init failed"
Your kernel may not support io-uring. Check:
```bash
uname -r  # Should be 5.1 or later
```

### Build Errors
```bash
# Clean and rebuild
rm -rf build
mkdir build
cd build
cmake ..
make
```

## Cross-Compilation

### For ARM64
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/arm64-toolchain.cmake ..
make
```

### For Raspberry Pi
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/rpi-toolchain.cmake ..
make
```

## Development Build

For development with debug symbols and sanitizers:

```bash
mkdir build-dev
cd build-dev
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fsanitize=address -fsanitize=undefined" \
      ..
make
```

## Static Analysis

### With clang-tidy
```bash
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
clang-tidy src/*.c -- -Iinclude
```

### With cppcheck
```bash
cppcheck --enable=all --inconclusive src/
```

## Performance Build

For maximum performance:

```bash
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-O3 -march=native -flto" \
      ..
make
```

## Testing the Build

### Quick Test
```bash
# Terminal 1: Start server
sudo ./build/vpn_server 4433 certs/server_cert.pem certs/server_key.pem

# Terminal 2: Start client
sudo ./build/vpn_client 127.0.0.1 4433

# Terminal 3: Test connectivity
ping 10.8.0.254  # Ping server through tunnel
```

### Check TUN Interfaces
```bash
ip addr show tun0  # Client
ip addr show tun1  # Server
```

## Cleaning

```bash
# Clean build directory
cd build
make clean

# Complete clean
cd ..
rm -rf build
```

## Next Steps

After building successfully:
1. Read [README.md](README.md) for usage instructions
2. Review [TUN_ARCHITECTURE.md](TUN_ARCHITECTURE.md) for system design
3. Check [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for development tips