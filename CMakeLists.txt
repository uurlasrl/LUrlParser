cmake_minimum_required(VERSION 3.0)

project("LUrlParser")

add_library(LUrlParser src/LUrlParser.cpp include/LUrlParser/LUrlParser.h)

target_include_directories(LUrlParser PUBLIC include)

add_library(LUrlParser::LUrlParser ALIAS LUrlParser)

#set_property(TARGET Example PROPERTY CXX_STANDARD 11)
#set_property(TARGET Example PROPERTY CXX_STANDARD_REQUIRED ON)
