# The subproject name
Project("freeDiameter simple daemon" C)

# Since it uses the libfdcore.h, it needs the include dependencies
#INCLUDE_DIRECTORIES("./include")
INCLUDE_DIRECTORIES(${LFDCORE_INCLUDES})
INCLUDE_DIRECTORIES("../third-party/libfdcore")
INCLUDE_DIRECTORIES("../third-party/libfdproto")

SET(SERVER_SRC ../src/fdServer.cpp)
SET(CLIENT_SRC ../src/fdClient.cpp)

ADD_LIBRARY(fdserver STATIC ${SERVER_SRC})
ADD_LIBRARY(fdclient STATIC ${CLIENT_SRC})

SET(SERVER_M main.cc)
SET(CLIENT_M mainClient.cc)
# Build the executable
ADD_EXECUTABLE(server ${SERVER_M} ${SERVER_SRC})
ADD_EXECUTABLE(client ${CLIENT_M} ${CLIENT_SRC})

# # The version
# SET_TARGET_PROPERTIES(server PROPERTIES 
# 	VERSION ${FD_PROJECT_VERSION_MAJOR}.${FD_PROJECT_VERSION_MINOR}.${FD_PROJECT_VERSION_REV})

# The link command
TARGET_LINK_LIBRARIES(server fdserver libfdproto libfdcore pcap ${GNUTLS_LIBRARIES} ${GCRYPT_LIBRARY})
TARGET_LINK_LIBRARIES(client fdclient libfdproto libfdcore pcap ${GNUTLS_LIBRARIES} ${GCRYPT_LIBRARY})

####
## INSTALL section ##

# INSTALL(TARGETS server
# 	RUNTIME DESTINATION ${INSTALL_DAEMON_SUFFIX}
# 	COMPONENT freeDiameter-daemon)
