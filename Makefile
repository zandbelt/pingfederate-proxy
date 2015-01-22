VERSION= 3.4

all: clean proxy-$(VERSION).zip

proxy-$(VERSION).zip: proxy.war
	zip -r $@ README proxy.jar $<
	rm -rf proxy.war

proxy.war:
	mkdir -p proxy.war/WEB-INF/lib
	mkdir -p proxy.war/META-INF
	cp WebContent/WEB-INF/web.xml proxy.war/WEB-INF
	cp WebContent/META-INF/MANIFEST.MF proxy.war/META-INF
	cp WebContent/proxy.properties proxy.war/
	cp WebContent/index.jsp proxy.war/
	jar cvf proxy.jar -C WebContent/WEB-INF/classes com

clean:
	rm -rf proxy.war proxy-$(VERSION).zip
