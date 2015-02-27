VERSION=4.0

all: clean proxy-$(VERSION).zip

proxy-$(VERSION).zip: proxy.war
	zip -r $@ README.md proxy.jar data.zip $<
	rm -rf proxy.war

proxy.war:
	mkdir -p proxy.war/WEB-INF/lib
	mkdir -p proxy.war/META-INF
	cp WebContent/WEB-INF/web.xml proxy.war/WEB-INF
	cp WebContent/META-INF/MANIFEST.MF proxy.war/META-INF
	cp WebContent/proxy.properties proxy.war/
	cp WebContent/dist/data.zip .
	jar cvf proxy.jar -C WebContent/WEB-INF/classes com

clean:
	rm -rf proxy.war proxy-$(VERSION).zip
