cmake_minimum_required(VERSION 3.20)
project(NetGuardianX VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 REQUIRED COMPONENTS Widgets Charts Network Core)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

set(MOC_HEADERS
    include/core/AppController.h
    include/gui/PacketContextManager.h
    include/gui/PacketStreamPanel.h
    include/gui/MainWindow.h
    include/gui/tabs/NetworkOverviewTab.h
    include/gui/tabs/DiagnosticsTab.h
    include/gui/tabs/TCPIPVisualizerTab.h
    include/gui/tabs/PacketDeepDiveTab.h
    include/gui/tabs/EndToEndFlowTab.h
    include/gui/tabs/BuffersQueuesTab.h
    include/gui/tabs/NICPhysicalTab.h
    include/gui/tabs/AutoHealingTab.h
)

qt6_wrap_cpp(MOC_GENERATED ${MOC_HEADERS})

set(CORE_SOURCES
    src/core/Logger.cpp
    src/core/eventbus/EventBus.cpp
    src/core/models/PacketModel.cpp
    src/core/parser/PacketParserPipeline.cpp
    src/core/capture/PacketCaptureEngine.cpp
    src/core/capture/SimulatedPacketSource.cpp
    src/core/monitoring/MonitoringEngine.cpp
    src/core/troubleshooting/TroubleshootingEngine.cpp
    src/core/healing/AutoHealingEngine.cpp
    src/core/nic/NICModule.cpp
    src/core/buffers/BufferModel.cpp
    src/core/PacketFilter.cpp
    src/core/AppController.cpp
)

set(GUI_SOURCES
    src/gui/PacketContextManager.cpp
    src/gui/PacketStreamPanel.cpp
    src/gui/MainWindow.cpp
    src/gui/tabs/NetworkOverviewTab.cpp
    src/gui/tabs/DiagnosticsTab.cpp
    src/gui/tabs/TCPIPVisualizerTab.cpp
    src/gui/tabs/PacketDeepDiveTab.cpp
    src/gui/tabs/EndToEndFlowTab.cpp
    src/gui/tabs/BuffersQueuesTab.cpp
    src/gui/tabs/NICPhysicalTab.cpp
    src/gui/tabs/AutoHealingTab.cpp
)

add_executable(NetGuardianX
    src/main.cpp
    ${CORE_SOURCES}
    ${GUI_SOURCES}
    ${MOC_GENERATED}
)

target_include_directories(NetGuardianX PRIVATE
    include
    ${PCAP_INCLUDE_DIRS}
)
target_compile_options(NetGuardianX PRIVATE -Wall -Wextra -O2 ${PCAP_CFLAGS_OTHER})
target_link_directories(NetGuardianX PRIVATE ${PCAP_LIBRARY_DIRS})
target_link_libraries(NetGuardianX PRIVATE
    Qt6::Widgets
    Qt6::Charts
    Qt6::Network
    Qt6::Core
    ${PCAP_LIBRARIES}
    pthread
)

add_executable(PipelineValidator
    tests/PipelineValidator.cpp
    src/core/Logger.cpp
    src/core/eventbus/EventBus.cpp
    src/core/models/PacketModel.cpp
    src/core/parser/PacketParserPipeline.cpp
    src/core/capture/SimulatedPacketSource.cpp
    src/core/monitoring/MonitoringEngine.cpp
)

target_include_directories(PipelineValidator PRIVATE
    include
    ${PCAP_INCLUDE_DIRS}
)
target_compile_options(PipelineValidator PRIVATE -Wall -Wextra -O2 ${PCAP_CFLAGS_OTHER})
target_link_directories(PipelineValidator PRIVATE ${PCAP_LIBRARY_DIRS})
target_link_libraries(PipelineValidator PRIVATE
    Qt6::Core
    ${PCAP_LIBRARIES}
    pthread
)

add_executable(Task18Verifier
    tests/Task18Verifier.cpp
    ${CORE_SOURCES}
    ${GUI_SOURCES}
    ${MOC_GENERATED}
)

target_include_directories(Task18Verifier PRIVATE
    include
    ${PCAP_INCLUDE_DIRS}
)
target_compile_options(Task18Verifier PRIVATE -Wall -Wextra -O2 ${PCAP_CFLAGS_OTHER})
target_link_directories(Task18Verifier PRIVATE ${PCAP_LIBRARY_DIRS})
target_link_libraries(Task18Verifier PRIVATE
    Qt6::Widgets
    Qt6::Charts
    Qt6::Network
    Qt6::Core
    ${PCAP_LIBRARIES}
    pthread
)
