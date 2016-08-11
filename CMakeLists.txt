cmake_minimum_required(VERSION 3.0.2)

project( SimpleLoader )

if( ${CMAKE_SIZEOF_VOID_P} EQUAL 8 )
set( CMAKE_X64 1 )
else()
set( CMAKE_X64 0 )
endif()

MACRO(SUBDIRLIST result curdir)
  FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
  SET(dirlist "")
  FOREACH(child ${children})
    IF(IS_DIRECTORY ${curdir}/${child})
        LIST(APPEND dirlist ${child})
    ENDIF()
  ENDFOREACH()
  SET(${result} ${dirlist})
ENDMACRO()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_PDB_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#allow source folders in VS solution
set_property(GLOBAL PROPERTY USE_FOLDERS ON) 

add_subdirectory(Loader)
add_subdirectory(TestDLL)
add_subdirectory(TestRun)
