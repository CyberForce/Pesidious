SAMPLES = address_convertions basic_dotnet_viewer basic_info_viewer bound_import_reader debug_info_reader entropy_calculator exception_dir_reader export_adder exports_reader full_pe_rebuilder image_config_editor import_adder imports_reader pe_config_reader pe_realigner pe_rebaser pe_sections_reader pe_stripper relocation_adder relocations_reader resource_editor resource_viewer rich_overlay_stub_reader section_adder sections_and_addresses tls_editor tls_reader
OUTDIR = ./out/
LIBPATH = ../lib/libpebliss.a
TARGETS = $(foreach sample,$(SAMPLES),$(sample)_sample)
TARGETS_CLEAN = $(foreach sample,$(SAMPLES),$(sample)_clean)

all: $(TARGETS)

clean: $(TARGETS_CLEAN)

$(OUTDIR):
	mkdir -p $(OUTDIR)

%_sample: $(OUTDIR) $(LIBPATH)
	$(MAKE) PE_DEBUG=$(PE_DEBUG) -C ./$*
	
%_clean:
	$(MAKE) -C ./$* clean
