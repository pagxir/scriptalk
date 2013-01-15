CXXFLAGS := -Ilibwait/include/ -DTIXML_USE_STL -D_USE_LIB_
LDFLAGS  := -Llibwait
LDLIBS   := -lwait -lrt -lssl
OBJECTS  := main.o gtalk.o tinyxml.o  \
	tinyxmlerror.o tinyxmlparser.o srvlookup.o parser.o

jxclient: $(OBJECTS) libwait/libwait.a
	$(CXX) -o jxclient $(LDFLAGS) $(OBJECTS) $(LDLIBS)

libwait/libwait.a:
	$(MAKE) -C libwait
