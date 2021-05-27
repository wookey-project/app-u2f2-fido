###################################################################
# About the application name and path
###################################################################

# Application name, can be suffixed by the SDK
APP_NAME ?= fido
# application build directory name
DIR_NAME = fido

# project root directory, relative to app dir
PROJ_FILES = ../../

# binary, hex and elf file names
BIN_NAME = $(APP_NAME).bin
HEX_NAME = $(APP_NAME).hex
ELF_NAME = $(APP_NAME).elf

# SDK helper Makefiles inclusion
-include $(PROJ_FILES)/m_config.mk
-include $(PROJ_FILES)/m_generic.mk

# application build directory, relative to the SDK BUILD_DIR environment
# variable.
APP_BUILD_DIR = $(BUILD_DIR)/apps/$(DIR_NAME)

###################################################################
# About the compilation flags
###################################################################

# SDK Cflags
CFLAGS := $(APPS_CFLAGS)
# Application CFLAGS...
CFLAGS += -Isrc/ -MMD -MP -O3
# libfido needs libecc
CFLAGS += -I$(PROJ_FILES)/externals/libecc/src $(EXTERNAL_CFLAGS) $(LIBSIGN_CFLAGS)
# App fido needs private key access. This access should be declared voluntary in makefiles
CFLAGS += -I$(PRIVATE_DIR)
# fido app uses the specialized FIDO profile (adding specific dedicated AUTH commands)
ifeq ($(CONFIG_PROJ_NAME),"u2f2")
CFLAGS += -DFIDO_PROFILE
endif

###################################################################
# About the link step
###################################################################


# linker options to add the layout file
LDFLAGS += $(EXTRA_LDFLAGS) -L$(APP_BUILD_DIR)
# project's library you whish to use...
LD_LIBS += -ltoken -lsmartcard -liso7816 -ldrviso7816 -lusart -laes -lcryp -lhmac -lstd -lsign -lu2f2 -lfido -Wl,--no-whole-archive

###################################################################
# okay let's list our source files and generated files now
###################################################################

CSRC_DIR = src
SRC = $(wildcard $(CSRC_DIR)/*.c)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(OBJ:.o=.d)

# the output directories, that will be deleted by the distclean target
OUT_DIRS = $(dir $(OBJ))

# the ldcript file generated by the SDK
LDSCRIPT_NAME = $(APP_BUILD_DIR)/$(APP_NAME).ld

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(OBJ) $(DEP) $(LDSCRIPT_NAME)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

############################################################
# explicit dependency on the application libs and drivers
# compiling the application requires the compilation of its
# dependencies
############################################################

## library dependencies
LIBDEP := $(BUILD_DIR)/libs/libstd/libstd.a \
		  $(BUILD_DIR)/libs/libfido/libfido.a \
		  $(BUILD_DIR)/libs/libhmac/libhmac.a \
		  $(BUILD_DIR)/libs/libu2f2/libu2f2.a \
		  $(BUILD_DIR)/externals/libsign.a


libdep: $(LIBDEP)

$(LIBDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)libs/$(patsubst lib%.a,%,$(notdir $@))


# drivers dependencies
#
SOCDRVDEP := 

socdrvdep: $(SOCDRVDEP)

$(SOCDRVDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)drivers/socs/$(SOC)/$(patsubst lib%.a,%,$(notdir $@))

# board drivers dependencies
BRDDRVDEP    :=

brddrvdep: $(BRDDRVDEP)

$(BRDDRVDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)drivers/boards/$(BOARD)/$(patsubst lib%.a,%,$(notdir $@))

# external dependencies
EXTDEP    :=

extdep: $(EXTDEP)

$(EXTDEP):
	$(Q)$(MAKE) -C $(PROJ_FILES)externals


alldeps: libdep socdrvdep brddrvdep extdep

##########################################################
# generic targets of all applications makefiles
##########################################################

show:
	@echo
	@echo "\t\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\t\tSRC\t=> " $(SRC)
	@echo "\t\tOBJ\t=> " $(OBJ)
	@echo "\t\tDEP\t=> " $(DEP)
	@echo
	@echo "\t\tCFG\t=> " $(CFLAGS)


# all (default) build the app
all: $(APP_BUILD_DIR) alldeps app


app: $(APP_BUILD_DIR)/$(ELF_NAME) $(APP_BUILD_DIR)/$(HEX_NAME)

$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)


# ELF
$(APP_BUILD_DIR)/$(ELF_NAME): $(OBJ)
	$(call if_changed,link_o_target)

# HEX
$(APP_BUILD_DIR)/$(HEX_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_ihex)

# BIN
$(APP_BUILD_DIR)/$(BIN_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_bin)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)


-include $(DEP)
