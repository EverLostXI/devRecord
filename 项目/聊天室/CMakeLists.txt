cmake_minimum_required(VERSION 3.10)

project(OnlineChatRoom)

add_executable(
    server
    server.cpp
)

target_link_libraries(
    server
    ws2_32
)