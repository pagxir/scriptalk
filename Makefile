CXXFLAGS := -Ilibwait/include/ -DTIXML_USE_STL
LDFLAGS  := -Llibwait
LDLIBS   := -lwait -lrt -lssl
OBJECTS  := main.o gtalk.o tinyxml.o  \
	tinyxmlerror.o tinyxmlparser.o srvlookup.o

jxclient: $(OBJECTS) libwait/libwait.a
	$(CXX) -o jxclient $(LDFLAGS) $(OBJECTS) $(LDLIBS)

libwait/libwait.a:
	$(MAKE) -C libwait
