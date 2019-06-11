# IMPORTANT NOTE
#
# These make commands do cd /dir && make ...
# and not make -C /dir ...
#
# We *cannot* do make -C /dir as it will break the kbuild process.
#
# It messes with paths used by the kbuild make process so that that no longer
# works

TF:=terraform
TFARGS:=
SSH_KEY:=~/.ssh/id_rsa.cray_openstack
SSH_USER:=root
SCP:=scp
SARGS:=-i $(SSH_KEY) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
SCP_ARGS+=$(SARGS)
SSH:=ssh
SSH_ARGS:=-q -ax $(SARGS)
V:=0
DEST:=/src
RESULTS:=/mnt/dvs/results
TAPRESULTS:=/mnt/dvs/tmp/latest

# all target does nothing now due to dynamic make targets
# TODO: find out some way to make this work again
all:
	@error "You must provide a target for this Makefile, the all target is not valid"

# ci target does the whole shebang from build to test, cleaning is optional
#
# Note: the multiple make invocations are very much intentional due to
# the dynamic make targets based on vm's being setup.
.PHONY: ci
ci:
	$(MAKE) up
	$(MAKE) -j rsync
	$(MAKE) -j dvs
	$(MAKE) -j install
	$(MAKE) -j load
	$(MAKE) test

.PHONY: init
init:
	$(TF) init

.terraform: init

# rebuild target just makes it easier to resync source and build it
.PHONY: rebuild
rebuild: rsync dvs

# If this fails, we try to ssh to localhost as a hack around not having
# anything in terraform outputs.
IPS:=$(shell terraform output 2>&1 | grep addresses | awk '{print $$3}' | tr ',' ' ' || echo 127.0.0.1)
IP:=$(shell terraform output 2>&1 | grep addresses | awk '{print $$3}' | awk -F, '{print $$1}' || echo 127.0.0.1)

# rsync target simply here to make it easier to rsync local checkout to remote
# systems for building there
#
# Note: rsync_ip targets are built dynamically when you run the makefile This
# lets us use gnu makes job functionality and rsync everywhere at once.
#
# DO NOT CHANGE THE ORDERING OF THESE TARGET DEFINITIONS!
# rsync, patch, dvs, install, load are doubly unique in that dependencies for it
# are determined at runtime and not statically.
#
# That is why these definitions look "weird" compared to normal make targets.
rsync: $(addprefix rsync_,$(IPS))
$(addprefix rsync_,$(IPS)): rsync_%:
	rsync --progress --filter 'P **/*.o' --filter 'P **/*.cmd' --checksum --delete-after -avLe '$(SSH) $(SSH_ARGS) -o BatchMode=yes' --exclude .git --exclude cray --exclude 'cscope.*' ../  root@$(shell echo $@ | sed -e 's/rsync_//'):$(DEST)
.PHONY: rsync $(addprefix rsync_,$(IPS))

# patch target just tries to apply test/debug patches to the current source
# already present in /src/$(DEST) across all nodes
patch: $(addprefix patch_,$(IPS))
$(addprefix patch_,$(IPS)): patch_%:
	$(SSH) $(SSH_ARGS) root@$(shell echo $@ | sed -e 's/patch_//') "cd $(DEST)/kernel && make patch"
.PHONY: patch $(addprefix patch_,$(IPS))

# dvs target is the build target to build dvs in /src/$(DEST)
dvs: $(addprefix dvs_,$(IPS))
$(addprefix dvs_,$(IPS)): dvs_%:
	$(SSH) $(SSH_ARGS) root@$(shell echo $@ | sed -e 's/dvs_//') "cd $(DEST)/kernel && make V=$(V) -j"
.PHONY: dvs $(addprefix dvs_,$(IPS))

# install target takes the newly built dvs modules and installs them to the
# local system
install: $(addprefix install_,$(IPS))
$(addprefix install_,$(IPS)): install_%:
	$(SSH) $(SSH_ARGS) root@$(shell echo $@ | sed -e 's/install_//') "cd $(DEST)/kernel && make install"
.PHONY: install $(addprefix install_,$(IPS))

# Load takes the (hopefully) already built dvs and then installs the kernel
# objects and then loads the dvs module
load: $(addprefix load_,$(IPS))
$(addprefix load_,$(IPS)): load_%:
	$(SSH) $(SSH_ARGS) root@$(shell echo $@ | sed -e 's/load_//') "cd $(DEST)/kernel && make load"
.PHONY: load $(addprefix load_,$(IPS))

# Unload tries to unload the dvs modules manually
unload: $(addprefix unload_,$(IPS))
$(addprefix unload_,$(IPS)): unload_%:
	$(SSH) $(SSH_ARGS) root@$(shell echo $@ | sed -e 's/unload_//') "cd $(DEST)/kernel && make unload"
.PHONY: unload $(addprefix unload_,$(IPS))

# Setup errors for any target that actually ends up hitting 127.0.0.1
BOGUS:=rsync_127.0.0.1 patch_127.0.0.1 dvs_127.0.0.1 install_127.0.0.1 load_127.0.0.1 unload 127.0.0.1
.PHONY: $(BOGUS)
$(BOGUS):
	@error terraform output didn\'t return a valid address for $<

# Clean any built dvs sources
clean-dvs: $(addprefix clean_dvs_,$(IPS))
$(addprefix clean_dvs_,$(IPS)): clean_dvs_%:
	$(SSH) $(SSH_ARGS) root@$(shell echo $@ | sed -e 's/clean_dvs_//') "cd $(DEST)/kernel && make clean"
.PHONY: clean-dvs $(addprefix clean_dvs_,$(IPS))

# TODO: Test target is/will be unique for multi-node. For now, its not working
# yet, it mounts on the first node and the other nodes are ignored. Will update
# this later.
#
# test target tries to run tests on the configured/built vm, alias for test-fast
.PHONY: test
test: test-fast

# test-fast target runs sharness with the default tests, aka tests that run
# quickly, target is we run in under 10 minutes for the whole target.
.PHONY: test-fast
test-fast:
	$(SSH) $(SSH_ARGS) root@$(IP) "make -C $(DEST)/test"

.PHONY: test-fstest
test-fstest:
	$(SSH) $(SSH_ARGS) root@$(IP) "make -C $(DEST)/test test-fstest"

.PHONY: test-sharness
test-sharness:
	$(SSH) $(SSH_ARGS) root@$(IP) "make -C $(DEST)/test test-sharness"

# Same as test-fast, but run sharness tests that take a long time to run
.PHONY: test-long
test-long: test-fstest test-long-only

# Same as test-just doesn't run fstest prior
.PHONY: test-long-only
test-long-only:
	$(SSH) $(SSH_ARGS) root@$(IP) "make -C $(DEST)/test test-long"


# results target is responsible for getting TAP test results out of the vm
#
# NOTE: return codes from scp are ignored.
.PHONY: results
results:
	-rsync --min-size=1 --progress --checksum --delete-after -avLe '$(SSH) $(SSH_ARGS) -o BatchMode=yes' root@$(IP):$(TAPRESULTS)/ tap-results
	-rsync --min-size=1 --progress --checksum --delete-after -avLe '$(SSH) $(SSH_ARGS) -o BatchMode=yes' root@$(IP):$(RESULTS)/ mnt-results

# Target to clean the ssh config of what we have setup, and add it back in.
.PHONY: ssh_config
ssh_config: clean_ssh_config add_ssh_config

# TODO: less copypasta... but doing $(MAKE) ... inserts the make output junk too
# Also, how could we distinguish different multiple separate dvs vm installations?
# Punting on that problem for now.
.PHONY: add_ssh_config
add_ssh_config:
	@(printf "# DVS VM SSH CONFIG START\n"; \
	for ip in $(IPS); do \
		hostname=`$(SSH) $(SSH_ARGS) $(SSH_USER)@$$ip uname -n`; \
		echo "host $$hostname"; \
		echo "  Hostname $$ip"; \
		echo "  User $(SSH_USER)"; \
		echo "  IdentityFile $(SSH_KEY)"; \
		echo "  StrictHostKeyChecking no"; \
		echo "  UserKnownHostsFile /dev/null"; \
		echo "  LogLevel QUIET"; \
	done; \
	printf "# DVS VM SSH CONFIG END\n") | tee -a ~/.ssh/config

# Remove the lines added above
.PHONY: clean_ssh_config
clean_ssh_config:
	perl -i -ne 'print unless /[#] DVS VM SSH CONFIG START/ .. /[#] DVS VM SSH CONFIG END/' ~/.ssh/config

# plan target to make it easier to run terraform plan
.PHONY: plan
plan:
	TF_VAR_ssh_key_file=$(SSH_KEY) $(TF) plan

# up target is simply terraform apply
.PHONY: up
up: .terraform plan
	TF_VAR_ssh_key_file=$(SSH_KEY) $(TF) $(TFARGS) apply -auto-approve

# clean target is simply terraform clean
.PHONY: clean
clean: clean_ssh_config
	TF_VAR_ssh_key_file=$(SSH_KEY) $(TF) $(TFARGS) destroy -auto-approve

# redo target just makes it easier to rebuild a vm
.PHONY: redo
redo: clean up

# distclean target removes all terraform state files. dangerous...
.PHONY: distclean
distclean: clean
	-rm -fr .terraform *.tfstate*
