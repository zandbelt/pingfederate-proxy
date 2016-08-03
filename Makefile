VERSION=4.9

all: clean proxy-$(VERSION).zip

proxy-$(VERSION).zip: proxy.war
	zip -r $@ README.md README.quickstart proxy.jar data.zip $<
	rm -rf proxy.war

proxy.war:
	mkdir -p proxy.war/WEB-INF/lib
	mkdir -p proxy.war/META-INF
	cp WebContent/WEB-INF/web.xml proxy.war/WEB-INF
	cp WebContent/META-INF/MANIFEST.MF proxy.war/META-INF
	cp WebContent/proxy.properties proxy.war/
	jar cvf proxy.jar -C bin com

clean:
	rm -rf proxy.war proxy-$(VERSION).zip
