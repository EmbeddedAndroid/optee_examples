project (optee_example_secvid C)

set (SRC host/main.c host/secvid_tee.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

# The GStreamer elements, on request (they need GStreamer for the target).
option(SECVID_GST "build the secvid GStreamer elements" OFF)
if(SECVID_GST)
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(SECVID_GST_DEPS REQUIRED gstreamer-1.0
			  gstreamer-base-1.0 gstreamer-allocators-1.0)
	add_library (gstsecvid MODULE host/gst/gstsecvid.c host/secvid_tee.c)
	target_include_directories(gstsecvid PRIVATE ta/include
				   ${SECVID_GST_DEPS_INCLUDE_DIRS})
	target_link_libraries (gstsecvid PRIVATE teec ${SECVID_GST_DEPS_LDFLAGS})
	install (TARGETS gstsecvid
		 DESTINATION ${CMAKE_INSTALL_LIBDIR}/gstreamer-1.0)
endif()
