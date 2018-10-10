
man_MANS = dvs.5

dvs.5: dvs.5.xml
	xml2roff $< > $@
	mklinks $<
	test.roff $@
