CXXFLAGS := -Ilibwait/include/ -DTIXML_USE_STL -D_USE_LIB_ -D_USE_PROXY_
LDFLAGS  := -Llibwait
LDLIBS   := -lwait -lrt -lpthread -lssl -lcrypto
OBJECTS  := main.o gtalk.o tinyxml.o  \
	tinyxmlerror.o tinyxmlparser.o \
	srvlookup.o parser.o base64.o

jxclient: $(OBJECTS) libwait/libwait.a
	$(CXX) -o jxclient $(LDFLAGS) $(OBJECTS) $(LDLIBS)

libwait/libwait.a:
	$(MAKE) -C libwait

clean:
	$(RM) *.o
