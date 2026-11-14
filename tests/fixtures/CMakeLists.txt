add_library(test_payload SHARED
    test_payload.cpp
)

target_compile_features(test_payload PRIVATE cxx_std_20)

set_target_properties(test_payload PROPERTIES
    PREFIX ""
    OUTPUT_NAME "test_payload"
)

if (MSVC)
    target_compile_options(test_payload PRIVATE /W4 /permissive- /guard:cf-)
    target_link_options(test_payload PRIVATE /GUARD:NO)
endif()
