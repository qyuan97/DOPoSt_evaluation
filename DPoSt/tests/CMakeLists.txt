include_directories(include tinymt64/include include)

add_executable(sha3 sha3.cpp)
target_link_libraries(sha3 cryptopp)

add_executable(hmac hmac_sha3.cpp ../include/toolkit.h)
target_link_libraries(hmac cryptopp)

add_executable(rsa rsa.cpp)
target_link_libraries(rsa cryptopp)

add_executable(post PoSt.cpp)
target_link_libraries(post cryptopp)

add_executable(dpost DPoSt.cpp muhash.cpp uint256.cpp chacha20.cpp util.h util.cpp base64.h sha256.h sha256.cpp)
target_link_libraries(dpost cryptopp)
target_link_libraries(dpost tinymt64)

add_executable(muhash main.cpp muhash.cpp uint256.cpp chacha20.cpp util.h util.cpp base64.h sha256.h sha256.cpp)