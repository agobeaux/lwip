include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)

set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/ubpf"
    "${LWIP_DIR}/src/include"
    "${LWIP_DIR}/contrib/"
    "${LWIP_DIR}/contrib/ports/unix/port/include"
    "${LWIP_DIR}/contrib/examples/example_app_client"
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/contrib/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/unix/Filelists.cmake)

# IMPORTANT TODO: generate ubpf/vm/libupf.a from the Makefile ubpf/vm/Makefile -> well, chez picoquic
#                 ils ne le font pas, ils disent dans le readme de make là-bas donc j'imagine qu'on oublie l'idée


add_executable(example_app_client ${LWIP_DIR}/contrib/examples/example_app_client/test.c default_netif.c)
target_include_directories(example_app_client PRIVATE ${LWIP_INCLUDE_DIRS})
target_compile_options(example_app_client PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(example_app_client PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_link_libraries(example_app_client ${LWIP_SANITIZER_LIBS} lwipcontribexamples lwipcontribapps lwipcontribaddons lwipallapps lwipcontribportunix lwipcore lwipmbedtls)


 # METTRE CECI DANS UN AUTRE DOSSIER JE PENSE!!! MAIS IL FAUT AUSSI
 # LINK LE NOUVEAU CMAKELISTS.TXT QUE J AURAI CREE AVEC LE CMAKDELISTS BASIQUE
 # -> CTRL+F DE UNIX/EXAMPLE_APP POUR VOIR CE QUI EST LINK.
 # PTET QUE CA FONCTIONNERA CETTE FOIS...
 # file:///home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/doc/doxygen/output/html/cmake.html
#add_executable(webserverupdated ${webserverupdated_SRCS})
#target_compile_options(webserverupdated PRIVATE ${LWIP_COMPILER_FLAGS})
#target_compile_definitions(webserverupdated PRIVATE ${LWIP_DEFINITIONS})
#target_include_directories(webserverupdated PRIVATE ${LWIP_INCLUDE_DIRS})
#target_link_libraries(webserverupdated ${LWIP_SANITIZER_LIBS} lwipcontribexamples lwipcontribapps lwipcontribaddons lwipallapps lwipcontribportunix lwipcore lwipmbedtls)


#add_executable(tcpechoserver ${tcpechoserver_SRCS})
#target_compile_options(tcpechoserver PRIVATE ${LWIP_COMPILER_FLAGS})
#target_compile_definitions(tcpechoserver PRIVATE ${LWIP_DEFINITIONS})
#target_include_directories(tcpechoserver PRIVATE ${LWIP_INCLUDE_DIRS})
#target_link_libraries(tcpechoserver ${LWIP_SANITIZER_LIBS} lwipcontribexamples lwipcontribapps lwipcontribaddons lwipallapps lwipcontribportunix lwipcore lwipmbedtls)
