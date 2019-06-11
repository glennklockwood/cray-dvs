RM:=rm
INSTALL:=install
RANDBYTE:=$(shell od -tx2 -N4 -An /dev/urandom | tr -cd [0-9a-f])
PROVE:=prove
TMPDIR:=/mnt/dvs/tmp
TMPNAM:=ci-prove-test
TMP:=$(TMPDIR)/$(TMPNAM)-$(RANDBYTE)
CWD:=$(shell pwd)
PERLLIB:=$(CWD)/p5lib/lib/perl5
TESTOUTPUT:=$(TMP)/results
ARCHIVEOPTS:=--merge --archive $(TESTOUTPUT)
PROVEOPTS:=-v --timer --state save
TESTS:=$(wildcard t*.t)
SHARNESSOPTS:=--verbose --immediate
SOPTS:=

.DEFAULT: all
.PHONY: all
all: test-fstest test-sharness

$(TMPDIR):
	install -dm755 $@

.PHONY: test-fast
test-fast: test-sharness test-fstest

# test-long is a lie, its just appending --long-tests to sharness scripts
# essentially test-sharness + --long-tests
.PHONY: test-long
test-long:
	$(MAKE) test-sharness SOPTS=--long-tests

.PHONY: test-sharness
test-sharness: $(TESTOUTPUT) $(TMPDIR)
	cd $(TESTOUTPUT)
	TARC=$(shell perldoc -l TAP::Harness::Archive | grep 'No documentation found')
	ln -sf $(TESTOUTPUT) $(TMPDIR)/latest
ifeq ($(strip "$(TARC)"),)
	@echo "TAP::Harness::Archive not present"
	$(PROVE) $(PROVEOPTS) $(POPTS) $(TESTS) :: $(SHARNESSOPTS) $(SOPTS) && echo "" || { cp $(CWD)/.prove $(TESTOUTPUT); exit 1; }
else
	$(PROVE) $(PROVEOPTS) $(ARCHIVEOPTS) $(POPTS) $(TESTS) :: $(SHARNESSOPTS) $(SOPTS) && echo "" || { cp $(CWD)/.prove $(TESTOUTPUT); exit 1; }
endif
	cp $(CWD)/.prove $(TESTOUTPUT)

$(TESTOUTPUT):
	$(INSTALL) -dm755 $@

.PHONY: clean
clean:
	-$(RM) -fr $(TESTOUTPUT) $(TMPDIR)/$(TMPNAM)* .prove trash\ directory.* test/trash\ directory.* test/test-results

.PHONY: test-fstest
test-fstest:
	$(CWD)/test_fstest.sh
