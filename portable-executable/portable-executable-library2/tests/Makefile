TESTS = tests_utils tests_basic test_rich_data test_entropy test_runner test_checksum test_tls test_relocations test_load_config test_exception_directory test_imports test_exports test_resources test_bound_import test_resource_viewer test_dotnet test_debug test_resource_manager test_resource_bitmap test_resource_icon_cursor test_resource_string_table test_resource_message_table test_resource_version_info
OUTDIR = ./bin/
LIBPATH = ../lib/libpebliss.a
TARGETS = $(foreach test,$(TESTS),$(test)_test)
TARGETS_CLEAN = $(foreach test,$(TESTS),$(test)_clean)

all: $(TARGETS) run_all_tests

clean: $(TARGETS_CLEAN)

$(OUTDIR):
	mkdir -p $(OUTDIR)

%_test: $(OUTDIR) $(LIBPATH)
	$(MAKE) PE_DEBUG=$(PE_DEBUG) -C ./$*
	
%_clean:
	$(MAKE) -C ./$* clean

run_all_tests:
	./bin/test_runner
