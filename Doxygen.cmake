# 문서는 main app일 때만 사용 가능하도록 함
find_package(Doxygen)

if(Doxygen_FOUND)
    set(DOXYGEN_PROJECT_NAME "a-ids")
    set(DOXYGEN_PROJECT_BRIEF "Orchid solutions ")
    set(DOXYGEN_PROJECT_NUMBER "${LIBRARY_VERSION}")

    # if (NOT DOXYGEN_OUTPUT_LANGUAGE OR DOXYGEN_OUTPUT_LANGUAGE MATCHES "[Ee]nglish")        # 입력값 없으면 영어 출력
    # set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "res/external/doxygen-manual/lang/en/Readme.md")
    # set(DOXYGEN_OUTPUT_LANGUAGE English)  # 영어 출력. 코드 내에서 \~english 으로 표시된 라인이 출력됨
    # set(DOXYGEN_OUTPUT_DIRECTORY manual_en)
    # file(GLOB MAN_FILES CONFIGURE_DEPENDS "res/external/doxygen-manual/lang/en/*")
    # set(ALL_MAN_FILES ${ALL_MAN_FILES} ${MAN_FILES})
    # else()
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "res/external/doxygen-manual/lang/kr/Readme.md")
    set(DOXYGEN_OUTPUT_LANGUAGE Korean) # 한국어 출력. 코드 내에서 \~korean 으로 표시된 라인이 출력됨
    set(DOXYGEN_OUTPUT_DIRECTORY manual_kr)
    file(GLOB MAN_FILES CONFIGURE_DEPENDS "res/external/doxygen-manual/lang/kr/*")
    set(ALL_MAN_FILES ${ALL_MAN_FILES} ${MAN_FILES})

    # endif()

    # file(GLOB MAN_FILES CONFIGURE_DEPENDS "res/external/doxygen-manual/lang/shared/*")
    # set(ALL_MAN_FILES ${ALL_MAN_FILES} ${MAN_FILES})
    set(DOXYGEN_HAVE_DOT YES) # 그래프 활성

    # if (True)                               # 기본 HTML로 생성. PDF 출력이 필요한 경우 False로 설정하시오
    set(DOXYGEN_HTML_COPY_CLIPBOARD YES)
    set(DOXTGEN_GENERATE_TREEVIEW YES)
    set(DOXTGEN_FULL_SIDEBAR YES)
    set(DOXYGEN_GENERATE_HTML YES)

    # else()
    # [Latex 사용 방법]
    # make docs 하여 latex 파일 생성 후 폴더 안에 들어가서 make pdf로 pdf 생성
    # (texlive-latex-extra 필요)
    # set(DOXYGEN_GENERATE_HTML NO)
    # set(DOXYGEN_GENERATE_LATEX YES)
    # set(DOXYGEN_USE_PDFLATEX YES)
    # set(DOXYGEN_LATEX_HEADER "header.tex")

    # set(DOXYGEN_GENERATE_RTF YES)
    # set(DOXYGEN_RTF_HYPERLINKS YES)
    # set(DOXYGEN_GENERATE_HTMLHELP YES)

    # endif()
    set(DOXYGEN_CREATE_SUBDIRS YES) # 구조 정리용
    set(DOXYGEN_ALPHABETICAL_INDEX YES) # 인덱스 활성
    set(DOXYGEN_IMAGE_PATH "res/external/doxygen-manual/img")
    set(DOXYGEN_SOURCE_BROWSER YES) # Raw 소스코드 활성
    set(DOXYGEN_VERBATIM_HEADERS YES) # Raw 소스코드 활성
    set(DOXYGEN_REFERENCES_LINK_SOURCE YES) # Raw 소스코드 활성

    # # Doxygen Awesome 관련
    # set(DOXYGEN_GENERATE_TREEVIEW YES)      # Required for Sidebar-only theme
    # set(DOXYGEN_HTML_EXTRA_STYLESHEET       # Required for Sidebar-only theme
    # "res/external/doxygen-awesome-css/doxygen-awesome.css"
    # "res/external/doxygen-awesome-css/doxygen-awesome-sidebar-only.css"
    # )
    # set(DOXYGEN_HTML_FOOTER "res/external/doxygen-awesome-css/footer.html")

    # 이하 추출될 내용 관련 설정
    set(DOXYGEN_EXTRACT_ALL YES) # 전 파일 탐색
    set(DOXYGEN_SHOW_FILES YES) # 파일 탭 표시 여부
    set(DOXYGEN_HIDE_UNDOC_MEMBERS NO) # 코멘트가 작성되지 않은 멤버 비등록(EXTRACT_ALL로 무효화)
    set(DOXYGEN_HIDE_UNDOC_CLASSES NO) # 코멘트가 작성되지 않은 클래스 비등록(EXTRACT_ALL로 무효화)
    set(DOXYGEN_HIDE_FRIEND_COMPOUNDS NO) # 모든 프랜드 비등록
    set(DOXYGEN_HIDE_IN_BODY_DOCS NO) # 펑션 바디 내 모든 코멘트 비등록

    set(DOXYGEN_SOURCE_BROWSER YES)
    set(DOXYGEN_INLINE_SOURCES YES)
    set(DOXYGEN_REFERENCED_BY_RELATION YES)
    set(DOXYGEN_REFERENCES_RELATION YES)
    set(DOXYGEN_REFERENCES_LINK_SOURCE YES)
    set(DOXYGEN_SOURCE_TOOLTIPS YES)
    set(DOXYGEN_ALPHABETICAL_INDEX YES)
    set(DOXYGEN_GENERATE_TREEVIEW YES)
    set(DOXYGEN_CLASS_GRAPH YES)
    set(DOXYGEN_COLLABORATION_GRAPH YES)
    set(DOXYGEN_CLASS_DIAGRAMS YES)
    set(DOXYGEN_GROUP_GRAPHS YES)
    set(DOXYGEN_UML_LOOK YES)
    set(DOXYGEN_UML_LIMIT_NUM_FIELDS 50)
    set(DOXYGEN_DOT_UML_DETAILS YES)
    set(DOXYGEN_DOT_WRAP_THRESHOLD 1000)
    set(DOXYGEN_INCLUDED_BY_GRAPH YES)
    set(DOXYGEN_CALL_GRAPH YES)
    set(DOXYGEN_CALLER_GRAPH YES)
    set(DOXYGEN_GRAPHICAL_HIERARCHY YES)
    set(DOXYGEN_DIRECTORY_GRAPH YES)
    set(DOXYGEN_DOT_IMAGE_FORMAT svg)
    set(DOXYGEN_INTERACTIVE_SVG YES)
    set(DOXYGEN_GENERATE_LEGEND YES)
    set(DOXYGEN_ENABLE_PREPROCESSING YES)
    set(DOXYGEN_SEARCH_INCLUDES YES)

    set(DOXYGEN_EXTRACT_PRIVATE YES)
    set(DOXYGEN_EXTRACT_PRIV_VIRTUAL YES)
    set(DOXYGEN_EXTRACT_STATIC YES)
    set(DOXYGEN_EXTRACT_LOCAL_METHODS YES)
    set(DOXYGEN_SHOW_INCLUDE_FILES YES)
    set(DOXYGEN_RECURSIVE YES)
    set(DOXYGEN_GENERATE_TREEVIEW YES)
    set(DOXYGEN_INCLUDE_GRAPH YES)
    set(DOXYGEN_DOT_IMAGE_FORMAT svg)
    set(DOXYGEN_DOT_GRAPH_MAX_NODES 200)
    set(DOXYGEN_DOT_CLEANUP NO)

    # set(DOXYGEN_ YES)
    # set(DOXYGEN_ YES)
    # set(DOXYGEN_ YES)
    # set(DOXYGEN_ YES)
    # set(DOXYGEN_ YES)
    # set(DOXYGEN_ YES)
    # set(DOXYGEN_ YES)

    # set(DOXYGEN_ YES)
    # set(DOXYGEN_ YES)

    # 제외할 파일 패턴
    set(DOXYGEN_EXCLUDE_PATTERNS
        */build*
        */CMakeFiles/*
        */testmaterial/*
        */common/inc/nlohmann*
    )

    set(DOX_SHARED_MATERIAL
        ${ALL_MAN_FILES}

        # traffic_injector/src/
        ${CMAKE_SOURCE_DIR}/aacrypt/src/
        ${CMAKE_SOURCE_DIR}/aacrypt/inc/
        ${CMAKE_SOURCE_DIR}/aatls/src/
        ${CMAKE_SOURCE_DIR}/aatls/inc/
        ${CMAKE_SOURCE_DIR}/common/src/
        ${CMAKE_SOURCE_DIR}/common/inc/
        ${CMAKE_SOURCE_DIR}/TlsComm/src/
    )

    # 배포용 문서
    doxygen_add_docs(
        docs
        ${DOX_SHARED_MATERIAL}
        COMMENT "${ACV2X_LIB_NAME} Man Pages"
    )

# # 개발용 문서(내부 API 등 포함)
# set(DOXYGEN_OUTPUT_DIRECTORY manual_dev)
# doxygen_add_docs(
# docs_dev
# ${DOX_SHARED_MATERIAL}
# ${PROJECT_SOURCE_DIR}/Readme_insiders.md
# ${PROJECT_SOURCE_DIR}/lcm
# ${PROJECT_SOURCE_DIR}/platformservice
# ${PROJECT_SOURCE_DIR}/credential
# ${PROJECT_SOURCE_DIR}/cryptofunction
# COMMENT "${ACV2X_LIB_NAME} Man Pages (for DEV)"
# )
else()
    message(STATUS "Doxygen not found, not building docs")
endif()
