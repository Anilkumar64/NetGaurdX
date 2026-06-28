# NetGuardianX

## Overview

NetGuardianX is an advanced, C++-based network security monitoring and diagnostic application featuring a rich Qt6 Graphical User Interface. It provides real-time traffic analysis, deep packet inspection, end-to-end flow visualization, buffer/queue insights, and automated troubleshooting capabilities to help you understand and secure your network infrastructure.

## Features

- **Real-Time Packet Capture**: High-performance network sniffing built on `libpcap`.
- **Comprehensive GUI**: A modern interface built with Qt6 featuring multiple specialized analysis tabs:
  - **Network Overview**: High-level statistics and active traffic trends.
  - **Diagnostics & Troubleshooting**: Identify misconfigurations and performance bottlenecks.
  - **TCP/IP Visualizer**: Deep dive into protocol mechanics.
  - **Packet Deep Dive**: Detailed packet hex dumps and header analysis.
  - **End-to-End Flow Analysis**: Track complete conversation streams.
  - **Buffers & Queues**: Monitor internal system queue behaviors.
  - **NIC Physical Insights**: Examine hardware-level network interface metrics.
  - **Auto-Healing**: Automated generation of fixes for common network issues.
- **Simulated Packet Source**: Includes a built-in traffic generator for development and testing without requiring live network access.

## Prerequisites

To build NetGuardianX, you need the following dependencies installed on your system:

- **C++20** compatible compiler (GCC or Clang)
- **CMake** (version 3.20 or higher)
- **Qt 6** (Requires `Widgets`, `Charts`, `Network`, and `Core` components)
- **libpcap** (`pkg-config` is used to locate it)

### Installing Dependencies (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install build-essential cmake qt6-base-dev qt6-charts-dev libpcap-dev pkg-config
```

## Build Instructions

NetGuardianX uses CMake for its build system. Follow these steps to compile the application:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Anilkumar64/NetGaurdX.git
   cd NetGuardianX
   ```

2. **Generate build files**:
   ```bash
   mkdir build
   cd build
   cmake ..
   ```

3. **Build the project**:
   ```bash
   cmake --build . -j$(nproc)
   ```

## Usage

After successfully building the project, you can launch the application from the `build` directory:

```bash
./NetGuardianX
```

### Running Tests

The project includes built-in verifiers and test executables. You can run them as follows:

```bash
# Run pipeline tests
./PipelineValidator

# Run specific task verifiers
./Task18Verifier
```

## Contributing

We welcome contributions! Please feel free to submit issues, fork the repository, and send pull requests.

## License

This project is open-source. Please see the LICENSE file for more information.
