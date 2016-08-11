cmake_minimum_required(VERSION 3.0.2)

project( TestDLL )

set( SOURCE TestDLL.cpp )

add_library( ${PROJECT_NAME} SHARED ${SOURCE} )

